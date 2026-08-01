// Package envelope is Otium's payload encryption format: AES-256-GCM under a per-payload
// data key, with the wrapped data key carried in the ciphertext's own header
// (docs/payload-encryption.md).
//
// One format serves both call sites — object storage (streaming, via Writer/Reader) and
// Postgres payload columns (one-shot, via Seal/Open) — so there is a single thing to get
// right and a single thing to test.
//
// The package is stdlib-only and holds no Otium types: it knows nothing about keyrings,
// jobs, or tenants beyond an opaque tenant string. Key wrapping is the caller's business
// (pkg/keyring), which keeps this lift-ready for go-toolkit and keeps the crypto testable
// without a vault.
//
// # Format
//
//	offset size  field
//	     0    8  magic "OTIUMENC"
//	     8    1  version
//	     9    1  algorithm
//	    10    2  tenant length       (big-endian uint16)
//	    12    2  key id length       (big-endian uint16)
//	    14    4  wrapped DEK length  (big-endian uint32)
//	    18    7  nonce prefix
//	    25    n  tenant
//	     .    m  key id
//	     .    k  wrapped DEK
//	  ---- chunks follow ----
//	  repeated: 4-byte big-endian length, then that many ciphertext bytes
//
// Each chunk is sealed with the same DEK under nonce = prefix(7) || counter(4) || final(1),
// with the header and a caller-supplied binding string as additional authenticated data.
// Three properties follow:
//
//   - Nonce reuse — GCM's catastrophic failure — cannot happen by accident: the prefix is
//     random per payload and the counter is monotonic.
//   - Truncation is detectable: only the last chunk sets the final flag, so a cut-short
//     stream fails to authenticate instead of decrypting to a plausible short payload.
//   - Relocation is detectable: the binding (an object key, or a job id and column) is
//     authenticated, so ciphertext moved elsewhere — or to another tenant — will not open.
package envelope

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Magic prefixes every envelope. Data that does not start with it is not an envelope —
// which is what lets the decrypt path pass legacy plaintext through untouched during
// rollout (docs/payload-encryption.md §6).
var Magic = []byte("OTIUMENC")

const (
	// Version1 is the current envelope version.
	Version1 = 1
	// AlgAES256GCM is AES-256-GCM with 1 MiB chunks.
	AlgAES256GCM = 1

	// ChunkSize is the plaintext bytes per sealed chunk. Bounds the working set: a
	// multi-gigabyte batch file encrypts in a megabyte of memory.
	ChunkSize = 1 << 20
	// gcmOverhead is the GCM authentication tag length.
	gcmOverhead = 16
	// maxChunkCipher caps a declared chunk length on read, so a corrupt or hostile
	// header cannot induce a huge allocation.
	maxChunkCipher = ChunkSize + gcmOverhead

	// headerFixed is the size of the fixed-width part of the header.
	headerFixed = 25
	// noncePrefixLen is the random per-payload portion of every chunk nonce.
	noncePrefixLen = 7
	// nonceLen is the GCM standard nonce size.
	nonceLen = 12

	// maxCounter is the highest chunk index a payload may reach before the counter
	// would wrap and reuse a nonce. At 1 MiB chunks this is ~4 PiB — unreachable in
	// practice, but the check exists so "in practice" never becomes an assumption.
	maxCounter = ^uint32(0) - 1
)

// Errors reported by this package.
var (
	// ErrNotEnvelope means the data does not begin with Magic — i.e. it is plaintext,
	// not corrupted ciphertext. Callers use this to pass legacy data through.
	ErrNotEnvelope = errors.New("envelope: not an envelope")
	// ErrCorrupt covers every failure to parse or authenticate: bad header, wrong
	// binding, tampered or truncated ciphertext. Deliberately undifferentiated — telling
	// a caller which check failed tells an attacker the same thing.
	ErrCorrupt = errors.New("envelope: corrupt or tampered ciphertext")
	// ErrUnsupported means the envelope was written by a newer version or with an
	// algorithm this build does not know. Distinct from ErrCorrupt because the fix is
	// to upgrade, not to restore from backup.
	ErrUnsupported = errors.New("envelope: unsupported version or algorithm")
	// ErrBadDEK means the supplied data key is not 32 bytes.
	ErrBadDEK = errors.New("envelope: data key must be 32 bytes")
	// ErrNoTenant means no tenant was supplied. Encrypting without one would defeat the
	// isolation the format exists to provide.
	ErrNoTenant = errors.New("envelope: tenant required")
)

// DEKSize is the required data-key length (AES-256).
const DEKSize = 32

// Params describe the key material and identity for one payload. The DEK encrypts the
// bytes; Wrapped is the same key sealed under the tenant's KEK and is stored in the header
// so the payload carries its own key. KeyID records which KEK version produced Wrapped,
// so a rotation never strands existing ciphertext.
type Params struct {
	Tenant  string
	KeyID   string
	DEK     []byte
	Wrapped []byte
	// Binding is authenticated but not stored: an object key, or "job:<id>:payload".
	// Ciphertext will not open under a different binding, which is what prevents a
	// storage-layer attacker from relocating one tenant's payload into another's slot.
	Binding string
}

func (p Params) validate() error {
	if p.Tenant == "" {
		return ErrNoTenant
	}
	if len(p.DEK) != DEKSize {
		return ErrBadDEK
	}
	if len(p.Wrapped) == 0 {
		return fmt.Errorf("envelope: wrapped data key is empty")
	}
	return nil
}

// header is the parsed form of an envelope header. Version and algorithm are validated
// during parsing rather than retained — a header that reaches this struct has already been
// accepted as version 1, AES-256-GCM.
type header struct {
	tenant      string
	keyID       string
	wrapped     []byte
	noncePrefix []byte
	// raw is the exact header bytes, authenticated as part of every chunk's AAD so the
	// tenant, key id, and wrapped key cannot be swapped without detection.
	raw []byte
}

// encodeHeader serializes a header for the given params and nonce prefix.
//
// The bounds are checked here rather than in validate(), so each narrowing conversion is
// provably in range at the point it happens instead of relying on a check several calls
// away. A header field that cannot be represented is an error, never a silent truncation —
// truncating a length would produce ciphertext nothing could ever open.
func encodeHeader(p Params, noncePrefix []byte) ([]byte, error) {
	// Bounds come from the width of the length fields themselves: two bytes for tenant and
	// key id, four for the wrapped key.
	if len(p.Tenant) > math.MaxUint16 {
		return nil, fmt.Errorf("envelope: tenant is %d bytes, limit %d", len(p.Tenant), math.MaxUint16)
	}
	if len(p.KeyID) > math.MaxUint16 {
		return nil, fmt.Errorf("envelope: key id is %d bytes, limit %d", len(p.KeyID), math.MaxUint16)
	}
	if len(p.Wrapped) > math.MaxUint32 {
		return nil, fmt.Errorf("envelope: wrapped key is %d bytes, limit %d", len(p.Wrapped), uint64(math.MaxUint32))
	}
	buf := make([]byte, headerFixed, headerFixed+len(p.Tenant)+len(p.KeyID)+len(p.Wrapped))
	copy(buf[0:8], Magic)
	buf[8] = Version1
	buf[9] = AlgAES256GCM
	// The three conversions below are bounded by the checks immediately above; gosec's
	// G115 does not trace the guard, so it is suppressed per line rather than package-wide.
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(p.Tenant)))  //nolint:gosec // G115: bounded above
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(p.KeyID)))   //nolint:gosec // G115: bounded above
	binary.BigEndian.PutUint32(buf[14:18], uint32(len(p.Wrapped))) //nolint:gosec // G115: bounded above
	copy(buf[18:25], noncePrefix)
	buf = append(buf, p.Tenant...)
	buf = append(buf, p.KeyID...)
	buf = append(buf, p.Wrapped...)
	return buf, nil
}

// parseHeaderFixed reads the fixed-width prefix, returning the variable-part length still
// to be read. It reports ErrNotEnvelope for data that simply is not an envelope, so callers
// can distinguish "plaintext" from "broken".
func parseHeaderFixed(b []byte) (tenantLen, keyIDLen int, wrappedLen int, err error) {
	if len(b) < headerFixed {
		return 0, 0, 0, ErrNotEnvelope
	}
	if string(b[0:8]) != string(Magic) {
		return 0, 0, 0, ErrNotEnvelope
	}
	if b[8] != Version1 || b[9] != AlgAES256GCM {
		return 0, 0, 0, ErrUnsupported
	}
	tenantLen = int(binary.BigEndian.Uint16(b[10:12]))
	keyIDLen = int(binary.BigEndian.Uint16(b[12:14]))
	wrapped := binary.BigEndian.Uint32(b[14:18])
	// A wrapped key is a few hundred bytes; anything near the uint32 ceiling is a
	// corrupt header trying to make us allocate.
	if wrapped > 1<<20 {
		return 0, 0, 0, ErrCorrupt
	}
	return tenantLen, keyIDLen, int(wrapped), nil
}

// nonce builds the chunk nonce: prefix || counter || final flag.
func nonce(prefix []byte, counter uint32, final bool) []byte {
	n := make([]byte, nonceLen)
	copy(n[:noncePrefixLen], prefix)
	binary.BigEndian.PutUint32(n[noncePrefixLen:noncePrefixLen+4], counter)
	if final {
		n[nonceLen-1] = 1
	}
	return n
}

// aad is the additional authenticated data for every chunk: the whole header plus the
// caller's binding.
func aad(rawHeader []byte, binding string) []byte {
	out := make([]byte, 0, len(rawHeader)+len(binding))
	out = append(out, rawHeader...)
	out = append(out, binding...)
	return out
}

// SealedSize returns the exact ciphertext length for a plaintext of n bytes under these params.
//
// It exists so a streaming writer can still declare its length. An S3 client given an unknown
// size cannot choose a part size, so it allocates a worst-case buffer per object — which
// OOM-killed the re-encryption Job after three files. The format is fully deterministic, so
// there is no reason to make the caller guess.
//
// Layout: the header, then one framed chunk per ChunkSize of plaintext plus a final chunk that
// is always emitted (possibly empty), each costing a 4-byte length prefix and a 16-byte tag.
func SealedSize(p Params, n int64) int64 {
	header := int64(headerFixed + len(p.Tenant) + len(p.KeyID) + len(p.Wrapped))
	chunks := n/int64(ChunkSize) + 1
	return header + chunks*int64(4+gcmOverhead) + n
}

// IsEnvelope reports whether b begins with the envelope magic. Used by the decrypt paths to
// pass through data written before encryption was enabled.
func IsEnvelope(b []byte) bool {
	return len(b) >= len(Magic) && string(b[:len(Magic)]) == string(Magic)
}

// HeaderTenant returns the tenant recorded in an envelope header without decrypting
// anything. Useful for operator tooling and for asserting that a stored object belongs to
// the tenant that asked for it. Returns ErrNotEnvelope for plaintext.
func HeaderTenant(b []byte) (string, error) {
	tenantLen, _, _, err := parseHeaderFixed(b)
	if err != nil {
		return "", err
	}
	if len(b) < headerFixed+tenantLen {
		return "", ErrCorrupt
	}
	return string(b[headerFixed : headerFixed+tenantLen]), nil
}

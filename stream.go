package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// UnwrapFunc unwraps a data key that was sealed under a tenant's KEK. Its signature matches
// keyring.Keyring.Unwrap exactly, so a Keyring's method value satisfies it — which is how
// this package stays free of any Otium import.
type UnwrapFunc func(ctx context.Context, tenant string, wrapped []byte, keyID string) ([]byte, error)

// Writer encrypts a stream into chunked envelope format. Callers write plaintext and must
// Close to flush the final chunk — Close is what marks the stream complete, so a Writer
// that is never closed produces ciphertext that deliberately fails to open.
type Writer struct {
	w       io.Writer
	aead    cipher.AEAD
	prefix  []byte
	ad      []byte
	buf     []byte
	counter uint32
	wrote   bool // header emitted
	closed  bool
	err     error
}

// NewWriter returns a Writer that encrypts to w. The header is emitted on the first Write
// or on Close, so an empty payload still produces a well-formed, authenticated envelope.
func NewWriter(w io.Writer, p Params) (*Writer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	aead, err := newAEAD(p.DEK)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, noncePrefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return nil, fmt.Errorf("envelope: nonce prefix: %w", err)
	}
	raw, err := encodeHeader(p, prefix)
	if err != nil {
		return nil, err
	}
	// Emit the header eagerly, so a Writer that is created and closed without a single
	// Write still produces a valid — empty, but authenticated — envelope.
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("envelope: write header: %w", err)
	}
	return &Writer{
		w:      w,
		aead:   aead,
		prefix: prefix,
		ad:     aad(raw, p.Binding),
		buf:    make([]byte, 0, ChunkSize),
	}, nil
}

func newAEAD(dek []byte) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, ErrBadDEK
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: gcm: %w", err)
	}
	return aead, nil
}

// Write implements io.Writer.
func (e *Writer) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.closed {
		return 0, errors.New("envelope: write after close")
	}
	written := 0
	for len(p) > 0 {
		space := ChunkSize - len(e.buf)
		n := min(space, len(p))
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(e.buf) == ChunkSize {
			// Not final: there may be more. The final chunk is emitted by Close.
			if err := e.flush(false); err != nil {
				e.err = err
				return written, err
			}
		}
	}
	return written, nil
}

// flush seals and emits the buffered chunk.
func (e *Writer) flush(final bool) error {
	if e.counter > maxCounter {
		return fmt.Errorf("envelope: payload exceeds the maximum chunk count")
	}
	sealed := e.aead.Seal(nil, nonce(e.prefix, e.counter, final), e.buf, e.ad)
	// Unreachable by construction — buf is capped at ChunkSize and GCM adds a fixed tag —
	// but checked so the narrowing below is provably in range rather than argued.
	if len(sealed) > maxChunkCipher || len(sealed) > math.MaxUint32 {
		return fmt.Errorf("envelope: sealed chunk is %d bytes, limit %d", len(sealed), maxChunkCipher)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed))) //nolint:gosec // G115: bounded above
	if _, err := e.w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("envelope: write chunk length: %w", err)
	}
	if _, err := e.w.Write(sealed); err != nil {
		return fmt.Errorf("envelope: write chunk: %w", err)
	}
	e.buf = e.buf[:0]
	e.counter++
	e.wrote = true
	return nil
}

// Close seals and writes the final chunk. It must be called: the final marker is what makes
// a complete stream distinguishable from a truncated one.
func (e *Writer) Close() error {
	if e.err != nil {
		return e.err
	}
	if e.closed {
		return nil
	}
	e.closed = true
	// Always emit a final chunk, even when empty — an empty payload must still be
	// authenticated end to end.
	return e.flush(true)
}

// Reader decrypts a chunked envelope stream.
type Reader struct {
	r       io.Reader
	aead    cipher.AEAD
	prefix  []byte
	ad      []byte
	plain   []byte // decrypted bytes not yet handed to the caller
	counter uint32
	done    bool // final chunk consumed
	tailOK  bool // verified that nothing follows the final chunk
	err     error
}

// NewReader reads the envelope header from r, unwraps its data key via unwrap, and returns
// a Reader over the plaintext.
//
// It returns ErrNotEnvelope if r does not begin with the magic — the caller decides whether
// that is legacy plaintext to pass through or an error. Note that the bytes already consumed
// from r cannot be un-read, so callers that need passthrough should use a buffered peek
// (objectstore.Encrypted does exactly this).
func NewReader(ctx context.Context, r io.Reader, binding string, unwrap UnwrapFunc) (*Reader, error) {
	fixed := make([]byte, headerFixed)
	if _, err := io.ReadFull(r, fixed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotEnvelope
		}
		return nil, fmt.Errorf("envelope: read header: %w", err)
	}
	tenantLen, keyIDLen, wrappedLen, err := parseHeaderFixed(fixed)
	if err != nil {
		return nil, err
	}
	rest := make([]byte, tenantLen+keyIDLen+wrappedLen)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, ErrCorrupt
	}
	h := header{
		tenant:      string(rest[:tenantLen]),
		keyID:       string(rest[tenantLen : tenantLen+keyIDLen]),
		wrapped:     rest[tenantLen+keyIDLen:],
		noncePrefix: fixed[18:25],
		raw:         append(fixed, rest...),
	}
	if h.tenant == "" {
		return nil, ErrCorrupt
	}
	dek, err := unwrap(ctx, h.tenant, h.wrapped, h.keyID)
	if err != nil {
		// Propagate verbatim: the caller must be able to tell an unavailable key
		// store (retryable) from a refused unwrap (not).
		return nil, err
	}
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	return &Reader{
		r:      r,
		aead:   aead,
		prefix: h.noncePrefix,
		ad:     aad(h.raw, binding),
	}, nil
}

// Read implements io.Reader.
func (d *Reader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			if err := d.checkTail(); err != nil {
				d.err = err
				return 0, err
			}
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}

// checkTail verifies nothing follows the final chunk. Without it, an attacker could append
// data to a stored object and the reader would silently ignore it — the object would no
// longer be what we wrote, while still opening cleanly. Probing costs one read at end of
// stream, which the underlying reader is about to hit anyway.
func (d *Reader) checkTail() error {
	if d.tailOK {
		return nil
	}
	var probe [1]byte
	n, err := d.r.Read(probe[:])
	if n > 0 {
		return ErrCorrupt
	}
	// A transport error at this point is indistinguishable from a clean end of stream
	// and is not evidence of tampering; treat it as the end.
	_ = err
	d.tailOK = true
	return nil
}

// next reads, authenticates, and buffers one chunk.
func (d *Reader) next() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(d.r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			// The stream ended without a final chunk: it was truncated.
			return ErrCorrupt
		}
		return fmt.Errorf("envelope: read chunk length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < gcmOverhead || n > maxChunkCipher {
		return ErrCorrupt
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(d.r, sealed); err != nil {
		return ErrCorrupt
	}
	// Try the non-final nonce first, then the final one. Exactly one can authenticate,
	// so this both decrypts the chunk and tells us whether the stream is complete.
	plain, err := d.aead.Open(nil, nonce(d.prefix, d.counter, false), sealed, d.ad)
	if err != nil {
		plain, err = d.aead.Open(nil, nonce(d.prefix, d.counter, true), sealed, d.ad)
		if err != nil {
			return ErrCorrupt
		}
		d.done = true
	}
	d.plain = plain
	d.counter++
	return nil
}

// Close implements io.Closer, closing the underlying reader when it is one.
func (d *Reader) Close() error {
	if c, ok := d.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

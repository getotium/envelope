package envelope

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// Seal encrypts plaintext into a single self-contained envelope. It is the one-shot form of
// Writer, for payloads that are already fully in memory — the jobs.payload and jobs.result
// columns, which are bounded by the submit API's request-size cap.
//
// The output is the same wire format Writer produces, so anything Seal writes, Reader can
// read and vice versa. There is exactly one format in the system.
func Seal(p Params, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	// Pre-size: header, one chunk length, the plaintext, and a tag per chunk.
	buf.Grow(headerFixed + len(p.Tenant) + len(p.KeyID) + len(p.Wrapped) +
		len(plaintext) + gcmOverhead + 4)

	w, err := NewWriter(&buf, p)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Open decrypts an envelope produced by Seal (or Writer) back into plaintext.
//
// It returns ErrNotEnvelope when data is not an envelope at all, which is how the rollout
// reads payloads written before encryption was enabled: the caller treats that error as
// "this is plaintext, use it verbatim" (docs/payload-encryption.md §6).
func Open(ctx context.Context, data []byte, binding string, unwrap UnwrapFunc) ([]byte, error) {
	if !IsEnvelope(data) {
		return nil, ErrNotEnvelope
	}
	r, err := NewReader(ctx, bytes.NewReader(data), binding, unwrap)
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if err != nil {
		// io.ReadAll surfaces the reader's error; keep it undifferentiated.
		if errors.Is(err, ErrCorrupt) {
			return nil, ErrCorrupt
		}
		return nil, err
	}
	return out, nil
}

// SealString and OpenString are string-typed conveniences for the Postgres payload columns,
// which are TEXT. The ciphertext is binary, so callers that need a text-safe representation
// must encode it — pkg/store does, and its column comment says so.
func SealString(p Params, plaintext string) ([]byte, error) {
	return Seal(p, []byte(plaintext))
}

// OpenString decrypts to a string.
func OpenString(ctx context.Context, data []byte, binding string, unwrap UnwrapFunc) (string, error) {
	out, err := Open(ctx, data, binding, unwrap)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

package envelope_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/getotium/envelope"
)

// testKey is a fixed data key; tests that need a second, different key use testKey2.
var (
	testKey  = bytes.Repeat([]byte{0x2A}, envelope.DEKSize)
	testKey2 = bytes.Repeat([]byte{0x3B}, envelope.DEKSize)
)

// unwrapTo returns an UnwrapFunc that always yields dek, standing in for a keyring. The
// keyring's own behavior is covered by pkg/keyring's conformance suite; here we isolate the
// format.
func unwrapTo(dek []byte) envelope.UnwrapFunc {
	return func(context.Context, string, []byte, string) ([]byte, error) { return dek, nil }
}

func params(binding string) envelope.Params {
	return envelope.Params{
		Tenant:  "acme",
		KeyID:   "otium-tenant-acme:v1",
		DEK:     testKey,
		Wrapped: []byte("wrapped-key-blob"),
		Binding: binding,
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"json payload", []byte(`{"model":"otium-medium","messages":[{"role":"user","content":"hi"}]}`)},
		{"exactly one chunk", bytes.Repeat([]byte("a"), envelope.ChunkSize)},
		{"one chunk plus a byte", bytes.Repeat([]byte("b"), envelope.ChunkSize+1)},
		{"several chunks", bytes.Repeat([]byte("c"), envelope.ChunkSize*3+17)},
		{"binary", []byte{0x00, 0xFF, 0x00, 0xFF}},
		{"unicode", []byte("héllo — wörld 🔐")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sealed, err := envelope.Seal(params("obj/key"), tc.plaintext)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if !envelope.IsEnvelope(sealed) {
				t.Fatal("sealed output is not recognized as an envelope")
			}
			if len(tc.plaintext) > 0 && bytes.Contains(sealed, tc.plaintext) {
				t.Fatal("plaintext appears verbatim in the ciphertext")
			}
			got, err := envelope.Open(ctx, sealed, "obj/key", unwrapTo(testKey))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("round trip mismatch: got %d bytes, want %d", len(got), len(tc.plaintext))
			}
		})
	}
}

// The binding is what stops ciphertext being relocated to another key or tenant slot.
func TestOpen_WrongBindingIsRefused(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("t/acme/batch/input/file-1"), []byte("secret prompt"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = envelope.Open(context.Background(), sealed, "t/globex/batch/input/file-1", unwrapTo(testKey))
	if !errors.Is(err, envelope.ErrCorrupt) {
		t.Fatalf("relocated ciphertext opened under a different binding: %v", err)
	}
}

func TestOpen_WrongKeyIsRefused(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := envelope.Open(context.Background(), sealed, "obj", unwrapTo(testKey2)); !errors.Is(err, envelope.ErrCorrupt) {
		t.Fatalf("ciphertext opened under the wrong data key: %v", err)
	}
}

// Every byte of the envelope is authenticated: header fields included.
func TestOpen_TamperingIsDetected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plaintext := bytes.Repeat([]byte("payload"), 200)

	sealed, err := envelope.Seal(params("obj"), plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"flipped ciphertext bit", func(b []byte) []byte {
			cp := bytes.Clone(b)
			cp[len(cp)-5] ^= 0x01
			return cp
		}},
		{"flipped tag bit", func(b []byte) []byte {
			cp := bytes.Clone(b)
			cp[len(cp)-1] ^= 0x80
			return cp
		}},
		{"altered tenant in header", func(b []byte) []byte {
			cp := bytes.Clone(b)
			i := bytes.Index(cp, []byte("acme"))
			copy(cp[i:], []byte("evil"))
			return cp
		}},
		{"altered key id in header", func(b []byte) []byte {
			cp := bytes.Clone(b)
			i := bytes.Index(cp, []byte("otium-tenant-acme:v1"))
			copy(cp[i:], []byte("otium-tenant-acme:v9"))
			return cp
		}},
		{"altered wrapped key", func(b []byte) []byte {
			cp := bytes.Clone(b)
			i := bytes.Index(cp, []byte("wrapped-key-blob"))
			copy(cp[i:], []byte("WRAPPED-key-blob"))
			return cp
		}},
		{"truncated mid-chunk", func(b []byte) []byte { return bytes.Clone(b[:len(b)-3]) }},
		{"appended garbage", func(b []byte) []byte {
			return append(bytes.Clone(b), 0xDE, 0xAD)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envelope.Open(ctx, tc.mutate(sealed), "obj", unwrapTo(testKey))
			if err == nil {
				t.Fatalf("tampered envelope opened successfully, yielding %d bytes", len(got))
			}
		})
	}
}

// The failure mode that would silently corrupt a batch result: a stream cut short must not
// decrypt to a valid-looking shorter payload.
func TestOpen_TruncatedStreamIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Three chunks, so we can drop the last one entirely and still have whole chunks.
	plaintext := bytes.Repeat([]byte("x"), envelope.ChunkSize*2+10)

	var buf bytes.Buffer
	w, err := envelope.NewWriter(&buf, params("obj"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	full := buf.Bytes()

	// Drop the final chunk (its 4-byte length, 10 plaintext bytes, and 16-byte tag). What
	// remains is a sequence of whole, individually valid chunks — only the missing final
	// marker reveals that the stream was cut short.
	truncated := full[:len(full)-(4+10+16)]

	if _, err := envelope.Open(ctx, truncated, "obj", unwrapTo(testKey)); err == nil {
		t.Fatal("a truncated stream decrypted successfully")
	}
}

// Rollout depends on this: data written before encryption was enabled must be
// distinguishable from ciphertext, not mistaken for corruption.
func TestOpen_PlaintextReportsNotEnvelope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"json", []byte(`{"model":"otium-medium"}`)},
		{"jsonl", []byte("{\"a\":1}\n{\"b\":2}\n")},
		{"short", []byte("hi")},
		{"almost magic", []byte("OTIUMEN")},
		{"wrong magic", []byte("OTIUMENX....................")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := envelope.Open(ctx, tc.data, "obj", unwrapTo(testKey)); !errors.Is(err, envelope.ErrNotEnvelope) {
				t.Errorf("got %v, want ErrNotEnvelope", err)
			}
		})
	}
}

func TestIsEnvelope(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !envelope.IsEnvelope(sealed) {
		t.Error("IsEnvelope was false for sealed output")
	}
	for _, b := range [][]byte{nil, []byte("plain"), []byte("OTIUMEN")} {
		if envelope.IsEnvelope(b) {
			t.Errorf("IsEnvelope was true for %q", b)
		}
	}
}

// Operator tooling must be able to attribute a stored object without holding any key.
func TestHeaderTenant(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tenant, err := envelope.HeaderTenant(sealed)
	if err != nil {
		t.Fatalf("HeaderTenant: %v", err)
	}
	if tenant != "acme" {
		t.Errorf("got %q, want %q", tenant, "acme")
	}
	if _, err := envelope.HeaderTenant([]byte("plaintext")); !errors.Is(err, envelope.ErrNotEnvelope) {
		t.Errorf("got %v, want ErrNotEnvelope", err)
	}
}

func TestSeal_RejectsBadParams(t *testing.T) {
	t.Parallel()
	base := params("obj")

	for _, tc := range []struct {
		name string
		mut  func(envelope.Params) envelope.Params
		want error
	}{
		{"no tenant", func(p envelope.Params) envelope.Params { p.Tenant = ""; return p }, envelope.ErrNoTenant},
		{"short dek", func(p envelope.Params) envelope.Params { p.DEK = []byte("short"); return p }, envelope.ErrBadDEK},
		{"nil dek", func(p envelope.Params) envelope.Params { p.DEK = nil; return p }, envelope.ErrBadDEK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := envelope.Seal(tc.mut(base), []byte("x")); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := envelope.Seal(func(p envelope.Params) envelope.Params { p.Wrapped = nil; return p }(base), []byte("x")); err == nil {
		t.Error("Seal accepted an empty wrapped key")
	}
}

// Two seals of identical plaintext under the same key must differ — otherwise an observer
// learns that two tenants submitted the same prompt.
func TestSeal_IsRandomized(t *testing.T) {
	t.Parallel()
	first, err := envelope.Seal(params("obj"), []byte("same plaintext"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := envelope.Seal(params("obj"), []byte("same plaintext"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals of the same plaintext produced identical ciphertext")
	}
}

// An unwrap failure must reach the caller intact, so a key store outage is distinguishable
// from tampering.
func TestNewReader_PropagatesUnwrapError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("key store unavailable")
	sealed, err := envelope.Seal(params("obj"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	failing := func(context.Context, string, []byte, string) ([]byte, error) { return nil, sentinel }
	if _, err := envelope.Open(context.Background(), sealed, "obj", failing); !errors.Is(err, sentinel) {
		t.Errorf("got %v, want the unwrap error to propagate", err)
	}
}

// The unwrap callback must receive exactly what the header recorded.
func TestNewReader_PassesHeaderToUnwrap(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var gotTenant, gotKeyID string
	var gotWrapped []byte
	capture := func(_ context.Context, tenant string, wrapped []byte, keyID string) ([]byte, error) {
		gotTenant, gotWrapped, gotKeyID = tenant, wrapped, keyID
		return testKey, nil
	}
	if _, err := envelope.Open(context.Background(), sealed, "obj", capture); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if gotTenant != "acme" {
		t.Errorf("tenant: got %q, want %q", gotTenant, "acme")
	}
	if gotKeyID != "otium-tenant-acme:v1" {
		t.Errorf("key id: got %q, want %q", gotKeyID, "otium-tenant-acme:v1")
	}
	if string(gotWrapped) != "wrapped-key-blob" {
		t.Errorf("wrapped: got %q", gotWrapped)
	}
}

// Streaming must produce byte-identical results to the one-shot form, and must not need the
// payload resident.
func TestWriterReader_Streaming(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plaintext := make([]byte, envelope.ChunkSize*2+1234)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var buf bytes.Buffer
	w, err := envelope.NewWriter(&buf, params("obj"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// Write in awkward sizes to exercise chunk-boundary handling.
	for off := 0; off < len(plaintext); off += 7777 {
		end := min(off+7777, len(plaintext))
		if _, err := w.Write(plaintext[off:end]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := envelope.NewReader(ctx, bytes.NewReader(buf.Bytes()), "obj", unwrapTo(testKey))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("streamed round trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

func TestWriter_WriteAfterCloseFails(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w, err := envelope.NewWriter(&buf, params("obj"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("late")); err == nil {
		t.Error("Write succeeded after Close")
	}
}

func TestWriter_DoubleCloseIsSafe(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w, err := envelope.NewWriter(&buf, params("obj"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// A Writer whose stream is never closed must not produce readable ciphertext — the final
// marker is the completeness signal.
func TestWriter_UnclosedStreamIsNotReadable(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w, err := envelope.NewWriter(&buf, params("obj"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("z"), envelope.ChunkSize)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Deliberately no Close.
	if _, err := envelope.Open(context.Background(), buf.Bytes(), "obj", unwrapTo(testKey)); err == nil {
		t.Fatal("an unclosed stream was readable")
	}
}

// A corrupt header must not be able to induce a huge allocation.
func TestNewReader_RejectsAbsurdLengths(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Wrapped-DEK length lives at offset 14..18.
	cp := bytes.Clone(sealed)
	cp[14], cp[15], cp[16], cp[17] = 0xFF, 0xFF, 0xFF, 0xFF
	if _, err := envelope.Open(context.Background(), cp, "obj", unwrapTo(testKey)); !errors.Is(err, envelope.ErrCorrupt) {
		t.Errorf("got %v, want ErrCorrupt", err)
	}
}

func TestNewReader_RejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"version", 8},
		{"algorithm", 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cp := bytes.Clone(sealed)
			cp[tc.offset] = 0x7F
			if _, err := envelope.Open(context.Background(), cp, "obj", unwrapTo(testKey)); !errors.Is(err, envelope.ErrUnsupported) {
				t.Errorf("got %v, want ErrUnsupported", err)
			}
		})
	}
}

// Documents the format's overhead so a change to it is a deliberate, visible decision.
func TestSeal_Overhead(t *testing.T) {
	t.Parallel()
	sealed, err := envelope.Seal(params("obj"), []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// header(25) + tenant(4) + keyID(20) + wrapped(16) + chunkLen(4) + tag(16) + 5 bytes
	const want = 25 + 4 + 20 + 16 + 4 + 16 + 5
	if len(sealed) != want {
		t.Errorf("envelope size: got %d, want %d — the format changed", len(sealed), want)
	}
}

func TestSeal_LargeTenantAndKeyID(t *testing.T) {
	t.Parallel()
	p := params("obj")
	p.Tenant = strings.Repeat("t", 300)
	p.KeyID = strings.Repeat("k", 300)
	sealed, err := envelope.Seal(p, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := envelope.Open(context.Background(), sealed, "obj", unwrapTo(testKey))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("got %q", got)
	}
	tenant, err := envelope.HeaderTenant(sealed)
	if err != nil {
		t.Fatalf("HeaderTenant: %v", err)
	}
	if tenant != p.Tenant {
		t.Error("long tenant did not survive the header round trip")
	}
}

func ExampleSeal() {
	p := envelope.Params{
		Tenant:  "acme",
		KeyID:   "otium-tenant-acme:v1",
		DEK:     bytes.Repeat([]byte{0x2A}, envelope.DEKSize),
		Wrapped: []byte("wrapped-by-the-keyring"),
		Binding: "t/acme/batch/input/file-1",
	}
	sealed, err := envelope.Seal(p, []byte("a customer prompt"))
	if err != nil {
		panic(err)
	}
	fmt.Println(envelope.IsEnvelope(sealed))
	// Output: true
}

// SealedSize must be EXACT, not an estimate: it is handed to the object store as the content
// length, so a wrong answer is a failed or truncated upload rather than a wasted byte.
func TestSealedSize_MatchesActual(t *testing.T) {
	t.Parallel()
	p := params("obj")

	for _, n := range []int{
		0, 1, 5, 4096,
		envelope.ChunkSize - 1, envelope.ChunkSize, envelope.ChunkSize + 1,
		envelope.ChunkSize * 2, envelope.ChunkSize*3 + 12345,
	} {
		sealed, err := envelope.Seal(p, bytes.Repeat([]byte("x"), n))
		if err != nil {
			t.Fatalf("Seal(%d): %v", n, err)
		}
		if got, want := envelope.SealedSize(p, int64(n)), int64(len(sealed)); got != want {
			t.Errorf("SealedSize(%d) = %d, actual ciphertext is %d", n, got, want)
		}
	}
}

# envelope

Chunked **AES-256-GCM** envelope encryption for payloads at rest — a small, dependency-free Go
package for encrypting blobs (object-storage objects, database columns) under a per-object data key,
where **key management is the caller's job**.

- **Stdlib-only.** No third-party dependencies. Nothing to audit but the standard `crypto` library.
- **Vault-agnostic.** The package never talks to a KMS. You supply an `UnwrapFunc` that turns the
  stored *wrapped* data-encryption key back into raw key bytes however you like — a cloud KMS, a
  Vault/OpenBao transit engine, an HSM, or an in-memory key for tests. So the same format works
  everywhere and is fully testable without any external service.
- **One format, two call sites.** One-shot `Seal`/`Open` for small values (e.g. a DB column), and
  streaming `Writer`/`Reader` for large blobs you don't want to hold in memory.
- **Tamper-evident + context-bound.** Every chunk is GCM-authenticated, and a `binding` string
  (e.g. a tenant or object id) is mixed into the additional authenticated data, so ciphertext can't
  be silently moved between contexts.

## How it works

The plaintext is split into fixed-size chunks, each sealed with AES-256-GCM under a random
**data-encryption key (DEK)**. The DEK is never stored in the clear — you wrap it (with your key
system) and the wrapped DEK + its key id ride in the ciphertext header. On open, the header's wrapped
DEK is handed back to your `UnwrapFunc` to recover the raw key, then each chunk is verified and
decrypted.

```go
type UnwrapFunc func(ctx context.Context, tenant string, wrapped []byte, keyID string) ([]byte, error)
```

## Install

```
go get github.com/getotium/envelope
```

## Usage

```go
// One-shot (small values):
sealed, err := envelope.Seal(params, plaintext)           // params carries the wrapped DEK + key id
plain, err  := envelope.Open(ctx, sealed, binding, unwrap) // unwrap recovers the raw DEK

// Streaming (large blobs):
w, err := envelope.NewWriter(dst, params)                  // dst is any io.Writer (e.g. an object-store upload)
// ... io.Copy(w, src) ...; w.Close()
r, err := envelope.NewReader(ctx, src, binding, unwrap)    // src is any io.Reader; read decrypted bytes out
```

`Seal` needs no context or vault call (it encrypts under a key you already hold, wrapped); `Open`
takes the `UnwrapFunc` because recovering the key is the only step that touches your key system.

## Provenance

Extracted from [Otium](https://getotium.ai)'s payload-encryption layer, where it encrypts customer
job payloads at rest under per-tenant keys. Published standalone so the data path is auditable.

## License

[Apache-2.0](LICENSE).

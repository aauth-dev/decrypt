# The secret.agent.coop message container

One format, forever (plan D19): a JWE ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)) with
`alg: ECDH-ES` and `enc: A256GCM` on a P-256 recipient key, **stored disassembled** (D18).
This document says exactly which bytes go where so any implementation can check itself against
the vectors in `vectors/`.

## Recipient keys

A recipient publishes one or more public keys, each `{kid, alg, jwk}`:

- `alg` is `ECDH-ES`.
- `jwk` is an EC P-256 public key: `{"kty":"EC","crv":"P-256","x":…,"y":…}`. No `d`, no `use`, no `key_ops`.
- `kid` is any printable ASCII string up to 128 characters the recipient chose. decrypt.agent.coop uses
  the RFC 7638 thumbprint of the public JWK (`BASE64URL(SHA-256('{"crv":"P-256","kty":"EC","x":"…","y":"…"}'))`),
  and senders MUST copy the `kid` exactly as published.

## Plaintext

One UTF-8 JSON object, encrypted whole (D3):

```json
{"text": "…", "attachments": [{"name": "…", "media_type": "…", "data": "<base64>"}]}
```

`text` up to 64 KB. Ciphertext up to 1 MiB (1,048,576 bytes). A decrypt service returns the parsed
object; if the plaintext is not a JSON object it returns it as `text`.

## Encryption

Standard JWE compact encryption, exactly as `jose` (Node) or `jwcrypto` (Python) produce it:

1. Protected header, JSON: `{"alg":"ECDH-ES","enc":"A256GCM","kid":"<recipient kid>","epk":{"kty":"EC","crv":"P-256","x":…,"y":…}}`.
   `epk` is the sender's fresh ephemeral public key. `apu` / `apv` MAY be present (RFC 7518 §4.6.1) and
   are honoured; nothing else in the header is interpreted.
2. `protected` = BASE64URL(UTF8(header JSON)). Its exact bytes are the AAD: never re-serialize it.
3. CEK = Concat KDF (RFC 7518 §4.6.2, SHA-256, one round) over the ECDH shared secret with
   `AlgorithmID = "A256GCM"`, `PartyUInfo = apu` (empty if absent), `PartyVInfo = apv` (empty if absent),
   `SuppPubInfo = 0x00000100` (256 bits). No `SuppPrivInfo`.
4. AES-256-GCM: 96-bit random IV, 128-bit tag, AAD = ASCII(`protected`).

Compact serialization is `protected..iv.ciphertext.tag` — the encrypted-key segment is empty for
ECDH-ES direct key agreement.

## The disassembled container

| Field | Where | Encoding |
| --- | --- | --- |
| `protected` | message metadata | base64url string, verbatim from the compact form |
| `iv` | message metadata | base64url, 12 bytes |
| `tag` | message metadata | base64url, 16 bytes |
| ciphertext | the blob | **raw bytes** = BASE64URL-decode of the compact form's fourth segment |

`kid` is read from the protected header. The service records size (ciphertext byte length),
sender, recipient, addresses, and times. Nothing else is derived from the container.

Reassembling the compact form for a standard library: `${protected}..${iv}.${BASE64URL(bytes)}.${tag}`.

## Wire forms

secret.agent.coop:

- `putBlob`: `PUT /messages/{id}/blob`, `Content-Type: application/octet-stream`, body = the raw
  bytes. Agents that can only send JSON (the AAuth MCP `invoke` tool) send
  `{"blob": "<base64url bytes>"}` with `Content-Type: application/json` instead.
- `getMessage`: `GET /messages/{id}` returns the raw bytes as `application/octet-stream`; with
  `Accept: application/json` it returns `{"id", "protected", "iv", "tag", "blob": "<base64url>"}`.

decrypt.agent.coop (`decryptEnvelope`, `POST /decrypt`):

- JSON: `{"protected", "iv", "tag", "ciphertext": "<base64url>"}`.
- Or raw bytes as `application/octet-stream` with `?protected=&iv=&tag=` query parameters.

## Vectors

`vectors/jose.json` and `vectors/jwcrypto.json` each hold a private key, the plaintext, the
compact JWE, and the four container fields. `test/decrypt.test.ts` loads each private key and
decrypts both with the Web Crypto implementation in `src/jwe.ts`, which shares no code with
either generator. Regenerate with `npm run vectors` and `python3 scripts/vectors_jwcrypto.py`.

## Refusals

| Code | Meaning |
| --- | --- |
| `unsupported_alg` / `unsupported_enc` | header is not `ECDH-ES` / `A256GCM` |
| `missing_kid` / `invalid_epk` / `invalid_iv` / `invalid_tag` / `invalid_protected_header` | malformed container |
| `unknown_kid` | the caller holds no key with that `kid` |
| `decrypt_failed` | GCM authentication failed: wrong key, or ciphertext, tag, IV, or header tampered |
| `payload_too_large` | ciphertext over 1 MiB |

# The secret.agent.coop message container

One format (plan D19, D27): a message is one JWE ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516))
in **compact serialization**, with `alg: ECDH-ES` and `enc: A256GCM` on a P-256 recipient key.
The messaging service stores the compact string whole and never takes it apart beyond reading
the protected header. This document says exactly which bytes go where so any implementation can
check itself against the vectors in `vectors/`.

Until D27 the container was stored disassembled (D18: `protected`, `iv`, `tag` in metadata, the
ciphertext as a blob). That form is gone; nothing reads or writes it.

## Recipient keys

A recipient has one current public key, `{kid, alg, jwk}`:

- `alg` is `ECDH-ES`.
- `jwk` is an EC P-256 public key: `{"kty":"EC","crv":"P-256","x":…,"y":…}`. No `d`, no `use`, no `key_ops`.
- `kid` is any printable ASCII string up to 128 characters. A read service built from this
  repository uses the RFC 7638 thumbprint of the public JWK
  (`BASE64URL(SHA-256('{"crv":"P-256","kty":"EC","x":"…","y":"…"}'))`), and senders MUST copy the
  `kid` exactly as published.

The messaging service holds the latest public key per person (`getPublicKey`). The read service
holds every private key, so a message encrypted to an older `kid` still decrypts after a rotation.

## Plaintext

One UTF-8 JSON object, encrypted whole:

```json
{"text": "…"}
```

`text` is up to 64 KB (65,536 bytes of UTF-8). `attachments` is a reserved member name; senders do
not produce it yet and readers ignore it. A read service returns `text`; if the plaintext is not a
JSON object with a string `text`, it returns the whole plaintext as `text` and adds the warning
`plaintext_not_json`.

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

## Compact serialization

RFC 7516 §7.1, five BASE64URL parts joined by `.`:

```
protected . encrypted_key . iv . ciphertext . tag
```

| Part | Content |
| --- | --- |
| `protected` | the protected header, verbatim; it is the AAD |
| `encrypted_key` | **empty** for `ECDH-ES` direct key agreement, so the string contains `..` |
| `iv` | 12 bytes |
| `ciphertext` | the AES-GCM ciphertext; at least one byte |
| `tag` | 16 bytes |

A valid container has exactly five parts, the second empty, the others non-empty and matching
`^[A-Za-z0-9_-]+$`. There is no JSON serialization, no unprotected header, and no second recipient.

## Sizes

- `text` up to 64 KB at the send service.
- The compact JWE up to 96 KB (98,304 characters) at the messaging service: 64 KB of plaintext is
  about 86 KB compact.

## Wire forms

The messaging service:

- `uploadMessage`: `POST /messages` `{"from", "to", "jwe": "<compact>"}`. It checks the header
  (`alg`, `enc`, `kid`, `epk`), that `kid` is the recipient's latest key, and the size.
- `downloadMessage`: `GET /messages/{id}` with `Accept: application/json` →
  `{"id", "from", "from_name", "to", "kid", "size", "created_at", "jwe": "<compact>"}`.
  `size` is the length of the compact string.

The read service (`readMessage`, `POST /read` `{"id", "resource"?}`) downloads the message over a
call chain, decrypts the `jwe` with the private key for its `kid`, and returns `text`. The send
service (`sendMessage`) is the reverse. Neither the compact string nor a private key passes
through the agent.

## Vectors

`vectors/jose.json` and `vectors/jwcrypto.json` each hold a private key, the plaintext, the
compact JWE, and its decoded protected header. `test/jwe.test.ts` decrypts both with the Web
Crypto implementation in `src/jwe.ts`, which shares no code with either generator. encrypt and
secret-agent-coop carry copies and test against them. Regenerate with `npm run vectors` and
`python3 scripts/vectors_jwcrypto.py` (`pip install jwcrypto`).

## Refusals

| Code | Where | Meaning |
| --- | --- | --- |
| `invalid_jwe` | messaging service, read service | not five parts with an empty second; header not `ECDH-ES` / `A256GCM`; no `kid` or `epk`; IV not 12 bytes or tag not 16 |
| `key_rotated` | messaging service | `kid` is not the recipient's latest key; fetch the key again |
| `too_large` | messaging service | compact JWE over 96 KB |
| `text_too_long` | send service | `text` over 64 KB |
| `unknown_kid` | read service | the caller holds no private key with that `kid` |
| `decrypt_failed` | read service | GCM authentication failed: wrong key, or a part was altered |

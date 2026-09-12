# decrypt-agent-coop

The decrypt service for [secret.agent.coop](https://secret.agent.coop): it holds the private key that decrypts your messages and decrypts them for your agent. This is the code that runs the hosted default at `decrypt.agent.coop`, and it is what you deploy to run your own.

**Status: not yet built.** The design is settled; code lands with stage 1 of the service.

## What it will be

- A Cloudflare Worker, an [AAuth](https://aauth.dev) resource with `access_mode: person-token`. Identity is the `(iss, sub)` pair from the person token, directed to this service. It never sees an email address.
- Operations: `GET /key` (current public key, created if none), `POST /key` (rotate), `POST /decrypt` (decrypt one message for the calling person), `GET /keys`, `DELETE /keys/{kid}` (per-call approval; destroys the private key).
- Keys: P-256, used as JWE `ECDH-ES` with `A256GCM`. One format, stored disassembled: protected header, IV, and tag travel as metadata; the ciphertext is raw bytes.
- Storage: D1 for multi-tenant, with private keys wrapped by a key-encryption secret. Single-tenant mode keeps `(iss, sub)` and the private key in Worker secrets and needs no database.
- Runs within the Workers Free plan CPU budget, so self-hosting costs nothing.

## Interop

The container format, its fields, and test vectors from `jose` (Node) and `jwcrypto` (Python) will live in `spec/` so any implementation can check itself against them.

## Self-hosting

Coming with the code: `wrangler deploy` on a free Cloudflare account, two secrets for single-tenant mode, then register the public key with secret.agent.coop from your agent.

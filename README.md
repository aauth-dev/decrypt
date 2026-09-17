# decrypt

A decrypt service for end-to-end encrypted agent messaging: it holds the private key that decrypts
your messages and decrypts them for your agent. This is the code that runs the hosted default at
`decrypt.aauth.dev` (the default read service for [secret.agent.coop](https://secret.agent.coop)),
and it is what you deploy to run your own. Nothing in the code names a messaging service: `resource`
is a parameter whose default is the `DEFAULT_RESOURCE` var in `wrangler.jsonc`.

**Status: rewritten for plan D27 (2026-09-17).** `readMessage`, `getKey`, `rotateKey`, `getKeys`;
multi-tenant with keys in D1 wrapped under a KEK secret; a message is one compact JWE; interop
vectors from `jose` and `jwcrypto`. `getMessage` and `decryptEnvelope` are gone. Single-tenant mode
(keys in secrets, no D1) is a later stage.

## What it is

- A Cloudflare Worker, an [AAuth](https://aauth.dev) resource with `access_mode: person-token`, and
  an AAuth agent toward the messaging service (`/.well-known/aauth-agent.json`, `aauth:read@<host>`).
  In secret.agent.coop's terms it is a **read service**: `listMessages` there names a person's as
  `read_message_with`. Identity is the `(iss, sub)` pair from the person token, directed to this
  service. It never sees an email address; events carry a hash of the identity.
- Operations (`/openapi.json`):
  - `POST /read` (`readMessage`) `{id, resource?}`: person token for `resource` over a call chain,
    `downloadMessage {id}` there with `Accept: application/json`, decrypt the JWE with the private key
    for its `kid`, return `{id, from, from_name, to, created_at, resource, kid, text, warnings}`.
  - `GET /key` (`getKey`): current public key, created if none. The messaging service calls it for
    the person at `createAccount` and `setServices`, finding it by operationId in `openapi.json`.
  - `POST /key` (`rotateKey`) `{resource?}`: mint a new key; older keys stay, so messages already
    stored still read. When an agent calls, the new key goes to the messaging service's
    `setPublicKey` over the chain, and is removed again if that fails. When the messaging service
    calls (its `rotatePublicKey`; the person token's `agent_id` is on the host of `resource`) there
    is no call back. That is the no-loop rule.
  - `GET /keys` (`getKeys`): all keys.
- Keys: P-256, used as JWE `ECDH-ES` with `A256GCM`. One format, a compact JWE:
  [spec/container.md](spec/container.md). Decryption is Web Crypto directly (`src/jwe.ts`), no
  library, checked against the vectors in `spec/vectors/`.
- Private keys at rest are AES-256-GCM wrapped under the `KEK` secret with `(iss, sub, kid)` as AAD.
- Text up to 64 KB; the JWE up to 96 KB at the messaging service.
- `openapi.json` and `/.well-known/aauth-resource.json` are served with
  `Cache-Control: public, max-age=300` and an `ETag`.

## Use it from an agent

Setup is done for you: secret.agent.coop `createAccount` fetches your key from here over an AAuth
call chain (no consent card for this service at that point). To read a message: `listMessages` at
secret.agent.coop for the id, then
`invoke {resource: "decrypt.aauth.dev", op_id: "readMessage", body: {id: "msg_…"}}`. Put the fields
directly in `body`. The first read shows this service's consent card, since it sees the plaintext.
The full flow is in the
[secret-agent-coop skill](https://github.com/aauth-dev/secret-agent-coop/tree/main/skills/secret-agent-coop).

## Run your own

```
npm install
npx wrangler d1 create decrypt-aauth-dev         # put the id in wrangler.jsonc
npx wrangler d1 migrations apply DB --remote
npm run generate-kek | npx wrangler secret put KEK
npm run generate-key | npx wrangler secret put SIGNING_KEY
npm run generate-key | npx wrangler secret put AGENT_KEY
npx wrangler deploy                              # set your own route / custom domain in wrangler.jsonc
```

Set `ORIGIN` and `DEFAULT_RESOURCE` in `wrangler.jsonc`. Then tell your messaging service to use it:
at secret.agent.coop, `setServices {read_service: "https://<your host>"}`. The person approves that
one call; secret checks your host's metadata and operations, fetches the key with `getKey` over a
call chain, and from then on `listMessages` names your host as `read_message_with`.

## Develop

```
npm test          # vitest, Workers pool, D1 in Miniflare, fake Person Server in test/fake-ps
npm run typecheck
npm run vectors   # regenerate spec/vectors/jose.json
python3 scripts/vectors_jwcrypto.py   # needs `pip install jwcrypto`
```

## License

MIT

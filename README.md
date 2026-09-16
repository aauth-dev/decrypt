# decrypt

A decrypt service for end-to-end encrypted agent messaging: it holds the private key that decrypts
your messages and decrypts them for your agent. This is the code that runs the hosted default at
`decrypt.aauth.dev` (the default decrypt service for [secret.agent.coop](https://secret.agent.coop)),
and it is what you deploy to run your own. Nothing in the code names a messaging service: the agent
brings the ciphertext, and secret registers whatever key you give it.

**Status: stage 1 built (2026-09-12), moved to decrypt.aauth.dev (2026-09-14).** `getKey`,
`rotateKey`, `getKeys`, `decryptEnvelope`; multi-tenant with keys in D1 wrapped under a KEK secret;
interop vectors from `jose` and `jwcrypto`; `/.well-known/aauth-agent.json` for the coming chained
download. Single-tenant mode (keys in secrets, no D1) and the chained download are later stages.

## What it is

- A Cloudflare Worker, an [AAuth](https://aauth.dev) resource with `access_mode: person-token`,
  hosted beside the other aauth.dev services.
  Identity is the `(iss, sub)` pair from the person token, directed to this service. It never sees an
  email address; events carry a hash of the identity.
- Operations (`/openapi.json`): `GET /key` current public key, created if none · `POST /key` mint a
  new key, older keys stay decryptable · `GET /keys` all keys · `POST /decrypt` decrypt one message.
- Keys: P-256, used as JWE `ECDH-ES` with `A256GCM`. One format, stored disassembled:
  [spec/container.md](spec/container.md). Decryption is Web Crypto directly (`src/jwe.ts`), no
  library, checked against the vectors in `spec/vectors/`.
- Private keys at rest are AES-256-GCM wrapped under the `KEK` secret with `(iss, sub, kid)` as AAD.
- Ciphertext up to 1 MiB. In the Workers test runtime a 1 MiB decrypt round trip (signature
  verification included) is about 60 ms wall; the Free-plan CPU figure on a real deployment is
  still to be read from Workers Logs.

## Use it from an agent

Setup is done for you: secret.agent.coop `createAccount` fetches your key from here over an AAuth
call chain and registers it (no consent card for this service at that point). The manual path is
`connect_resources [{resource: "decrypt.aauth.dev"}]`, `invoke getKey`, then `addKey {kid, alg, jwk}`
at secret. To read a message: `getMessage` at secret.agent.coop (JSON form), then `decryptEnvelope`
here with `{protected, iv, tag, ciphertext}` where `ciphertext` is the `blob` field. The first read
shows this service's consent card, since it sees the plaintext. The full flow is in the
[secret-agent-coop skill](https://github.com/aauth-dev/secret-agent-coop/tree/main/skills/secret-agent-coop).

## Run your own

```
npm install
npx wrangler d1 create decrypt-agent-coop        # put the id in wrangler.jsonc
npx wrangler d1 migrations apply DB --remote
npm run generate-kek | npx wrangler secret put KEK
npm run generate-key | npx wrangler secret put SIGNING_KEY
npx wrangler deploy                              # set your own route / custom domain in wrangler.jsonc
```

Then `connect_resources` your host from your agent, `getKey`, and register that key at your
messaging service (secret.agent.coop `addKey`). secret does not need to know where the private key
lives (plan D16).

## Develop

```
npm test          # vitest, Workers pool, D1 in Miniflare, fake Person Server in test/fake-ps
npm run typecheck
npm run vectors   # regenerate spec/vectors/jose.json
python3 scripts/vectors_jwcrypto.py   # needs `pip install jwcrypto`
```

## License

MIT

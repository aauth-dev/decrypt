// readMessage (plan read-send-services section 7b): the chained download
// and decrypt, against the fake PS (HTTP person_token_endpoint) and a fake
// messaging service at a non-agent.coop host. `resource` is a parameter and
// its default comes from DEFAULT_RESOURCE. Every status code of 7b; an older
// message after a rotation (5d); both interop vectors read end to end.
import { beforeAll, describe, expect, it } from 'vitest'
import { env } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { CompactEncrypt, decodeJwt, importJWK } from 'jose'
import { Agent, FakePS, FakeSecret, RESOURCE, SECRET } from './fake-ps'
import { wrapPrivateJwk } from '../src/kek'
import joseVector from '../spec/vectors/jose.json'
import jwcryptoVector from '../spec/vectors/jwcrypto.json'

let ps: FakePS
let secret: FakeSecret
let alice: Agent
let bob: Agent

const BOB = { handle: 'bob', email: 'bob@example.com' }

interface Key { kid: string; jwk: JsonWebKey }
interface Read { id: string; from: string; from_name?: string; to: string; created_at: string; resource: string; kid: string; text: string; warnings: string[] }
interface Refusal { error: string; detail?: string; step?: string; resource?: string; field?: string; id?: string }

let counter = 0
/** Put a compact JWE in bob's inbox at the fake messaging service. */
async function deliver(jwe: string): Promise<string> {
  const id = `msg_in${String(++counter).padStart(20, '0')}_000`
  secret.inbox.set(id, { id, sub: await ps.sub(BOB, SECRET), from: 'mailto:Alice@example.com', from_name: 'Alice Doe', to: 'mailto:bob@example.com', jwe, state: 'new' })
  return id
}
/** Encrypt `plaintext` to a key the way a send service does, and deliver it. */
async function deliverTo(key: Key, plaintext: string, kid = key.kid): Promise<string> {
  const jwe = await new CompactEncrypt(new TextEncoder().encode(plaintext)).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid }).encrypt(await importJWK(key.jwk as never, 'ECDH-ES'))
  return deliver(jwe)
}
const currentKey = async () => (await bob.json<Key>('GET', '/key')).body
const read = (agent: Agent, body: Record<string, unknown>) => agent.json<Read & Refusal>('POST', '/read', { body })

beforeAll(async () => {
  ps = await new FakePS().init()
  secret = new FakeSecret(ps)
  alice = await new Agent(ps, { handle: 'alice', email: 'alice@example.com' }, RESOURCE).init()
  bob = await new Agent(ps, BOB, RESOURCE).init()
  clearMetadataCache()
})

describe('readMessage (7b)', () => {
  it('200: downloads over the chain asking for JSON, decrypts, returns the text with who it is from', async () => {
    const key = await currentKey()
    const id = await deliverTo(key, JSON.stringify({ text: 'hi bob' }))
    const { status, body } = await read(bob, { id, resource: SECRET })
    expect(status).toBe(200)
    expect(body).toEqual({ id, from: 'mailto:Alice@example.com', from_name: 'Alice Doe', to: 'mailto:bob@example.com', created_at: expect.any(String), resource: SECRET, kid: key.kid, text: 'hi bob', warnings: [] })
    expect(secret.requests.at(-1)).toBe(`GET /messages/${id}`)
    expect(secret.downloadAccepts.at(-1)).toBe('application/json')
    expect(secret.inbox.get(id)!.state).toBe('downloaded')
    // The chain: Bob's directed sub at the messaging service, and this service's agent id on the token (10).
    expect(secret.seen.at(-1)).toBe(await ps.sub(BOB, SECRET))
    expect(secret.agentIds.at(-1)).toBe('aauth:read@decrypt.aauth.dev')
    expect(decodeJwt(ps.lastAgentToken!).sub).toBe('aauth:read@decrypt.aauth.dev')
    // Required by Hellō since Wallet 2026.9.24 (#4302): 401 without one.
    expect(decodeJwt(ps.lastAgentToken!).jti).toEqual(expect.stringMatching(/^[0-9a-f-]{36}$/))
  })

  it('resource is optional: the default is DEFAULT_RESOURCE (Q7)', async () => {
    const id = await deliverTo(await currentKey(), JSON.stringify({ text: 'from the default' }))
    const { status, body } = await read(bob, { id })
    expect(status).toBe(200)
    expect(body).toMatchObject({ text: 'from the default', resource: env.DEFAULT_RESOURCE })
    expect(env.DEFAULT_RESOURCE).toBe(SECRET)
  })

  for (const vector of [joseVector, jwcryptoVector]) {
    it(`reads the ${vector.generator} vector's compact JWE end to end`, async () => {
      const sub = await ps.sub(BOB, RESOURCE)
      const wrapped = await wrapPrivateJwk(env.KEK, ps.iss, sub, vector.kid, vector.private_jwk as JsonWebKey)
      await env.DB.prepare('INSERT OR REPLACE INTO private_keys (ps_iss, ps_sub, kid, alg, private_jwk, public_jwk, created_at, retired_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(ps.iss, sub, vector.kid, 'ECDH-ES', wrapped, JSON.stringify(vector.public_jwk), '2000-01-01T00:00:00.000Z', '2000-01-02T00:00:00.000Z')
        .run()
      const { status, body } = await read(bob, { id: await deliver(vector.compact) })
      expect(status).toBe(200)
      expect(body).toMatchObject({ kid: vector.kid, text: (JSON.parse(vector.plaintext) as { text: string }).text, warnings: [] })
    })
  }

  it('a message stored under an older kid still reads after a rotation (5d)', async () => {
    const old = await currentKey()
    const id = await deliverTo(old, JSON.stringify({ text: 'sent before the rotation' }))
    const rotated = await bob.json<Key>('POST', '/key')
    expect(rotated.status).toBe(200)
    expect(rotated.body.kid).not.toBe(old.kid)
    const { status, body } = await read(bob, { id })
    expect(status).toBe(200)
    expect(body).toMatchObject({ kid: old.kid, text: 'sent before the rotation' })
  })

  it('plaintext that is not {"text": …} comes back whole as text with a warning', async () => {
    const key = await currentKey()
    for (const plaintext of ['just text', JSON.stringify({ body: 'no text member' }), JSON.stringify(['a'])]) {
      const { status, body } = await read(bob, { id: await deliverTo(key, plaintext) })
      expect(status).toBe(200)
      expect(body).toMatchObject({ text: plaintext, warnings: ['plaintext_not_json'] })
    }
  })

  it('a system message comes back as the messaging service sent it', async () => {
    const id = `msg_sys${String(++counter).padStart(19, '0')}_000`
    secret.inbox.set(id, { id, sub: await ps.sub(BOB, SECRET), from: 'mailto:system@agent.coop', to: 'mailto:bob@example.com', system: { type: 'connection_added', peer_address: 'mailto:Alice@example.com', peer_name: 'Alice Doe' }, state: 'new' })
    const { status, body } = await read(bob, { id })
    expect(status).toBe(200)
    expect(body).toMatchObject({ id, system: { type: 'connection_added', peer_name: 'Alice Doe' }, resource: SECRET, warnings: [] })
    expect(body).not.toHaveProperty('text')
  })

  it('400 invalid_request: id is required and an id; resource, when given, must be an https origin', async () => {
    const id = await deliverTo(await currentKey(), 'x')
    for (const b of [{}, { id: 7 }, { id: 'has space' }, { id: 'x'.repeat(65) }]) {
      const { status, body } = await read(bob, b)
      expect(status, JSON.stringify(b)).toBe(400)
      expect(body).toMatchObject({ error: 'invalid_request', field: 'id' })
    }
    for (const resource of ['http://secret.fake.test', `${SECRET}/`, `${SECRET}/messages`, 'secret.fake.test', null]) {
      const { status, body } = await read(bob, { id, resource })
      expect(status, String(resource)).toBe(400)
      expect(body).toMatchObject({ error: 'invalid_request', field: 'resource' })
    }
    expect(secret.inbox.get(id)!.state).toBe('new')
  })

  it("refusals from the messaging service pass through with step download_message: alice cannot read bob's message", async () => {
    const id = await deliverTo(await currentKey(), 'for bob')
    const { status, body } = await read(alice, { id })
    expect(status).toBe(404)
    expect(body).toEqual({ error: 'not_found', step: 'download_message', resource: SECRET })
    expect(secret.inbox.get(id)!.state).toBe('new')
  })

  it('404 unknown_kid: no private key of the caller matches the JWE kid; carries the message id', async () => {
    const id = await deliverTo(await currentKey(), 'x', 'not-a-kid')
    const { status, body } = await read(bob, { id })
    expect(status).toBe(404)
    expect(body).toMatchObject({ error: 'unknown_kid', id, kid: 'not-a-kid', from: 'mailto:Alice@example.com' })
    expect(body.step).toBeUndefined()
  })

  it('422 decrypt_failed: a JWE altered after encryption', async () => {
    const key = await currentKey()
    const jwe = await new CompactEncrypt(new TextEncoder().encode('{"text":"x"}')).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: key.kid }).encrypt(await importJWK(key.jwk as never, 'ECDH-ES'))
    const parts = jwe.split('.')
    parts[3] = parts[3].slice(0, -1) + (parts[3].endsWith('A') ? 'B' : 'A')
    const { status, body } = await read(bob, { id: await deliver(parts.join('.')) })
    expect(status).toBe(422)
    expect(body.error).toBe('decrypt_failed')
  })

  it('502 when the messaging service answers with something that is not a compact JWE', async () => {
    const { status, body } = await read(bob, { id: await deliver('not.a.jwe') })
    expect(status).toBe(502)
    expect(body).toMatchObject({ error: 'invalid_jwe', step: 'download_message' })
  })

  it('502 step person_token: a chain the PS refuses', async () => {
    const id = await deliverTo(await currentKey(), 'x')
    ps.expectedIntermediary = 'https://someone-else.test'
    try {
      const { status, body } = await read(bob, { id })
      expect(status).toBe(502)
      expect(body).toMatchObject({ error: 'invalid_upstream_token', step: 'person_token', resource: SECRET })
    } finally {
      ps.expectedIntermediary = undefined
    }
  })
})

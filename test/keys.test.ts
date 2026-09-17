// The public surface and the keys: one per directed identity, created on the
// first getKey, wrapped at rest, all of them kept. readMessage is in
// read.test.ts, rotateKey in rotate.test.ts, the container in jwe.test.ts.
import { beforeAll, describe, expect, it } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { Agent, FakePS, FakeSecret, RESOURCE, SECRET } from './fake-ps'

let ps: FakePS
let alice: Agent
let bob: Agent

interface Key { kid: string; alg: string; jwk: JsonWebKey; created_at: string }

beforeAll(async () => {
  ps = await new FakePS().init()
  new FakeSecret(ps)
  alice = await new Agent(ps, { handle: 'alice', email: 'alice@example.com' }, RESOURCE).init()
  bob = await new Agent(ps, { handle: 'bob', email: 'bob@example.com' }, RESOURCE).init()
  clearMetadataCache()
})

describe('public surface', () => {
  it('well-known is person-token with the OpenAPI vocabulary; the name is the origin host', async () => {
    const meta = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)).json()) as Record<string, unknown>
    expect(meta).toMatchObject({ issuer: RESOURCE, name: new URL(RESOURCE).host, access_mode: 'person-token' })
  })
  it('OpenAPI is the operations of 7a: readMessage, getKey, rotateKey, getKeys; getMessage and decryptEnvelope are gone', async () => {
    const spec = (await (await SELF.fetch(`${RESOURCE}/openapi.json`)).json()) as { paths: Record<string, Record<string, { operationId: string; requestBody?: { content: Record<string, { schema: { required?: string[]; properties: Record<string, { description: string }> } }> } }>> }
    const ops = Object.entries(spec.paths).flatMap(([path, item]) => Object.entries(item).map(([m, op]) => `${op.operationId} ${m.toUpperCase()} ${path}`))
    expect(ops.sort()).toEqual(['getKey GET /key', 'getKeys GET /keys', 'readMessage POST /read', 'rotateKey POST /key'])
    const read = spec.paths['/read'].post.requestBody!.content['application/json'].schema
    expect(read.required).toEqual(['id'])
    expect(read.properties.resource.description).toContain(env.DEFAULT_RESOURCE)
    expect(env.DEFAULT_RESOURCE).toBe(SECRET)
  })
  it('the removed routes answer 404', async () => {
    expect((await alice.call('POST', '/decrypt', { body: { protected: 'a', iv: 'b', tag: 'c', ciphertext: 'd' } })).status).toBe(404)
    expect((await alice.call('GET', `/messages/msg_x?resource=${encodeURIComponent(SECRET)}`)).status).toBe(404)
  })
  it('unsigned GET /key is a person-token challenge', async () => {
    const res = await SELF.fetch(`${RESOURCE}/key`)
    expect(res.status).toBe(401)
    expect(res.headers.get('aauth-requirement')).toBe('requirement=person-token')
  })
  it('serves aauth-agent.json naming this origin and its JWKS', async () => {
    const doc = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-agent.json`)).json()) as Record<string, unknown>
    expect(doc.issuer).toBe(RESOURCE)
    expect(doc.name).toBe(new URL(RESOURCE).host)
    expect(doc.jwks_uri).toBe(`${RESOURCE}/.well-known/jwks.json`)
    const jwks = (await (await SELF.fetch(doc.jwks_uri as string)).json()) as { keys: Array<Record<string, unknown>> }
    expect(jwks.keys[0].alg).toBe('Ed25519')
    expect(jwks.keys[0].kid).toBeTypeOf('string')
  })
})

describe('keys', () => {
  let aliceKey: Key
  it('getKey creates a P-256 key on first call and returns the same one after', async () => {
    const first = await alice.json<Key>('GET', '/key')
    expect(first.status).toBe(200)
    aliceKey = first.body
    expect(aliceKey.alg).toBe('ECDH-ES')
    expect(aliceKey.jwk).toMatchObject({ kty: 'EC', crv: 'P-256' })
    expect((aliceKey.jwk as { d?: string }).d).toBeUndefined()
    const second = await alice.json<Key>('GET', '/key')
    expect(second.body.kid).toBe(aliceKey.kid)
  })
  it('another identity gets a different key', async () => {
    const { body } = await bob.json<Key>('GET', '/key')
    expect(body.kid).not.toBe(aliceKey.kid)
  })
  it('after a rotation the new key is current and the old one is still listed', async () => {
    const rotated = await alice.json<Key>('POST', '/key')
    expect(rotated.status).toBe(200)
    expect(rotated.body.kid).not.toBe(aliceKey.kid)
    const current = await alice.json<Key>('GET', '/key')
    expect(current.body.kid).toBe(rotated.body.kid)
    const { body } = await alice.json<{ keys: Key[] }>('GET', '/keys')
    expect(body.keys.map((k) => k.kid).sort()).toEqual([aliceKey.kid, rotated.body.kid].sort())
  })
  it('the stored private key is wrapped, not plaintext', async () => {
    const row = await env.DB.prepare('SELECT private_jwk FROM private_keys WHERE kid = ?').bind(aliceKey.kid).first<{ private_jwk: string }>()
    expect(row!.private_jwk).not.toContain('"d"')
    expect(row!.private_jwk).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  })
})

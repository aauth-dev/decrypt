// rotateKey (plan read-send-services sections 5b, 5c): when the agent calls,
// the new key goes to the messaging service's setPublicKey over a call
// chain; when the messaging service calls (its rotatePublicKey), there is
// no call back. That is the no-loop rule on this side. A failed
// setPublicKey leaves the key unchanged.
import { beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { env } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { Agent, FakePS, FakeSecret, RESOURCE, SECRET } from './fake-ps'

let ps: FakePS
let secret: FakeSecret
/** Bob's agent through the AAuth MCP */
let bob: Agent
/** The messaging service chaining here for Bob's rotatePublicKey: its agent id is on the token */
let secretForBob: Agent

const BOB = { handle: 'bob', email: 'bob@example.com' }
const SECRET_AGENT = `aauth:account@${new URL(SECRET).host}`

interface Key { kid: string; alg: string; jwk: JsonWebKey; created_at: string }
interface Rotated extends Key { resource?: string; set_public_key?: { kid: string; created_at: string } }
interface Refusal { error: string; detail?: string; step?: string; resource?: string; field?: string }

const kids = async () => (await bob.json<{ keys: Key[] }>('GET', '/keys')).body.keys.map((k) => k.kid)
const current = async () => (await bob.json<Key>('GET', '/key')).body.kid

beforeAll(async () => {
  ps = await new FakePS().init()
  secret = new FakeSecret(ps)
  bob = await new Agent(ps, BOB, RESOURCE).init()
  secretForBob = await new Agent(ps, BOB, RESOURCE, SECRET_AGENT).init()
  clearMetadataCache()
  await bob.json('GET', '/key')
})

let setCalls: number
let chainCalls: number
beforeEach(() => {
  setCalls = secret.setPublicKeyCalls.length
  chainCalls = ps.personTokenRequests
})

describe('rotation from the read service (5c): the agent calls rotateKey', () => {
  it('mints a key, chains to setPublicKey {kid, alg, jwk}, returns the key and the messaging service\'s answer', async () => {
    const before = await current()
    const { status, body } = await bob.json<Rotated>('POST', '/key', { body: { resource: SECRET } })
    expect(status).toBe(200)
    expect(body.kid).not.toBe(before)
    expect(body).toMatchObject({ alg: 'ECDH-ES', jwk: { kty: 'EC', crv: 'P-256' }, resource: SECRET, set_public_key: { kid: body.kid, created_at: expect.any(String) } })
    expect(secret.setPublicKeyCalls.slice(setCalls)).toEqual([{ kid: body.kid, alg: 'ECDH-ES', jwk: body.jwk }])
    expect(secret.requests.at(-1)).toBe('PUT /public-key')
    // The messaging service saw this read service's agent id and Bob's directed sub there.
    expect(secret.agentIds.at(-1)).toBe('aauth:read@decrypt.aauth.dev')
    expect(secret.publicKeys.get(await ps.sub(BOB, SECRET))!.kid).toBe(body.kid)
    expect(await current()).toBe(body.kid)
  })
  it('resource is optional: the default is DEFAULT_RESOURCE; no body at all works', async () => {
    const { status, body } = await bob.json<Rotated>('POST', '/key')
    expect(status).toBe(200)
    expect(body.resource).toBe(env.DEFAULT_RESOURCE)
    expect(secret.setPublicKeyCalls).toHaveLength(setCalls + 1)
  })
  it('a PS that puts no agent_id on the token is treated as an agent: setPublicKey is called', async () => {
    const quiet = await new Agent(ps, BOB, RESOURCE, null).init()
    const { status } = await quiet.json<Rotated>('POST', '/key')
    expect(status).toBe(200)
    expect(secret.setPublicKeyCalls).toHaveLength(setCalls + 1)
  })
  it('403 not_read_service from the messaging service passes through with step set_public_key; the key is unchanged', async () => {
    const before = { current: await current(), kids: await kids() }
    secret.readServiceHost = 'some-other-read.example'
    try {
      const { status, body } = await bob.json<Refusal>('POST', '/key')
      expect(status).toBe(403)
      expect(body).toMatchObject({ error: 'not_read_service', step: 'set_public_key', resource: SECRET })
    } finally {
      secret.readServiceHost = new URL(RESOURCE).host
    }
    expect({ current: await current(), kids: await kids() }).toEqual(before)
  })
  it('502 step person_token when the PS refuses the chain; the key is unchanged', async () => {
    const before = { current: await current(), kids: await kids() }
    ps.expectedIntermediary = 'https://someone-else.test'
    try {
      const { status, body } = await bob.json<Refusal>('POST', '/key')
      expect(status).toBe(502)
      expect(body).toMatchObject({ error: 'invalid_upstream_token', step: 'person_token' })
    } finally {
      ps.expectedIntermediary = undefined
    }
    expect({ current: await current(), kids: await kids() }).toEqual(before)
    expect(secret.setPublicKeyCalls).toHaveLength(setCalls)
  })
  it('400 invalid_request: resource, when given, must be an https origin; nothing is minted', async () => {
    const before = await kids()
    const { status, body } = await bob.json<Refusal>('POST', '/key', { body: { resource: 'http://secret.fake.test' } })
    expect(status).toBe(400)
    expect(body).toMatchObject({ error: 'invalid_request', field: 'resource' })
    expect(await kids()).toEqual(before)
  })
})

describe('rotation from secret (5b): the messaging service calls rotateKey', () => {
  it('mints and returns {kid, alg, jwk}; no setPublicKey, no chain: no loop', async () => {
    const before = await current()
    const { status, body } = await secretForBob.json<Rotated>('POST', '/key', { body: { resource: SECRET } })
    expect(status).toBe(200)
    expect(body.kid).not.toBe(before)
    expect(body).toMatchObject({ alg: 'ECDH-ES', jwk: { kty: 'EC', crv: 'P-256' } })
    expect(body).not.toHaveProperty('set_public_key')
    expect(secret.setPublicKeyCalls).toHaveLength(setCalls)
    expect(ps.personTokenRequests).toBe(chainCalls)
    expect(await current()).toBe(body.kid)
  })
  it('the same with no body: the caller is the default messaging service', async () => {
    const { status } = await secretForBob.json<Rotated>('POST', '/key')
    expect(status).toBe(200)
    expect(secret.setPublicKeyCalls).toHaveLength(setCalls)
    expect(ps.personTokenRequests).toBe(chainCalls)
  })
  it('an agent id on another host than resource is an agent, not the messaging service', async () => {
    const lookalike = await new Agent(ps, BOB, RESOURCE, `aauth:account@${new URL(SECRET).host}.evil.example`).init()
    const { status } = await lookalike.json<Rotated>('POST', '/key')
    expect(status).toBe(200)
    expect(secret.setPublicKeyCalls).toHaveLength(setCalls + 1)
  })
})

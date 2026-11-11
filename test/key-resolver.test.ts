// Key discovery (src/key-resolver.ts): one @hellocoop/httpsig key resolver on
// one store for the token's issuer (requireIdentity) and for a server signing
// a revocation as itself; every fetch is an aauth.decrypt.key_fetch event.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'
import { clearKeyCache } from '../src/key-resolver'
import { Agent, FakePS, PS, RESOURCE, now } from './fake-ps'

const ALICE = { handle: 'alice', email: 'alice@example.com' }
const UNREACHABLE = 'https://unreachable-ps.fake.test'

let ps: FakePS
let alice: Agent
let events: Array<Record<string, any>>
let spy: MockInstance

beforeAll(async () => {
  ps = await new FakePS().init()
  alice = await new Agent(ps, ALICE, RESOURCE).init()
})

beforeEach(() => {
  clearKeyCache()
  events = []
  spy = vi.spyOn(console, 'log').mockImplementation((line: unknown) => {
    try {
      const o = JSON.parse(String(line))
      if (o?.event === 'aauth.decrypt.key_fetch') events.push(o)
    } catch {
      /* not one of ours */
    }
  })
})

afterEach(() => spy.mockRestore())

const getKey = async (jwt: string) => alice.signed(jwt, 'GET', `${RESOURCE}/key`, {})

describe('key discovery', () => {
  it('a cold lookup fetches the issuer metadata and JWKS once each, one key_fetch event per fetch; the next request is served from the cache', async () => {
    expect((await getKey(await ps.personToken(ALICE, alice.key))).status).toBe(200)
    expect(events).toHaveLength(2)
    const [metadata, jwks] = events
    expect(metadata).toMatchObject({
      service: 'decrypt', level: 30, route: '/key', method: 'GET',
      doc: 'metadata', url: `${PS}/.well-known/aauth-person.json`, id: PS, dwk: 'aauth-person.json', reason: 'cold', ok: true, status: 200,
      msg: `metadata fetch ok (cold): ${PS}/.well-known/aauth-person.json`,
    })
    expect(metadata.duration_ms).toBeTypeOf('number')
    expect(metadata.ttl_ms).toBeTypeOf('number')
    expect(jwks).toMatchObject({ doc: 'jwks', url: `${PS}/jwks.json`, id: PS, reason: 'cold', ok: true, status: 200 })

    expect((await getKey(await ps.personToken(ALICE, alice.key))).status).toBe(200)
    expect(events).toHaveLength(2)
  })

  it('a failed fetch is a level 40 event, and is not retried within the refetch floor', async () => {
    const jwt = await ps.personToken(ALICE, alice.key, RESOURCE, { iss: UNREACHABLE })
    let res = await getKey(jwt)
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('metadata_fetch_failed')
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({ level: 40, doc: 'metadata', url: `${UNREACHABLE}/.well-known/aauth-person.json`, reason: 'cold', ok: false })
    expect(events[0].msg).toBe(`metadata fetch failed (cold): ${UNREACHABLE}/.well-known/aauth-person.json`)

    res = await getKey(jwt)
    expect(res.status).toBe(401)
    expect(events).toHaveLength(1)
  })

  it('a revocation signer and a token from the same issuer share one cache', async () => {
    expect((await ps.revoke(`${RESOURCE}/aauth/revoke`, { jti: `never-${crypto.randomUUID()}`, exp: now() + 300 })).status).toBe(200)
    expect(events.map((e) => [e.doc, e.route])).toEqual([['metadata', '/aauth/revoke'], ['jwks', '/aauth/revoke']])

    expect((await getKey(await ps.personToken(ALICE, alice.key))).status).toBe(200)
    expect(events).toHaveLength(2)
  })
})

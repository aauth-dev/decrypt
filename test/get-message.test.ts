// decrypt.aauth.dev getMessage (D1): the chained download against the fake
// PS (HTTP person_token_endpoint) and a fake messaging service at a
// non-agent.coop host, so the target resource is proven to be a parameter.
import { beforeAll, describe, expect, it } from 'vitest'
import { SELF } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { CompactEncrypt, decodeJwt, importJWK } from 'jose'
import { Agent, FakePS, FakeSecret, RESOURCE, SECRET } from './fake-ps'

let ps: FakePS
let secret: FakeSecret
let alice: Agent
let bob: Agent

const BOB = { handle: 'bob', email: 'bob@example.com' }

interface Key { kid: string; jwk: JsonWebKey }
interface Read { id: string; from: string; to: string; resource: string; kid: string; size: number; plaintext?: unknown; text?: string; warnings: string[] }
interface Refusal { error: string; detail?: string; step?: string; resource?: string }

function b64urlDecode(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

let counter = 0
/** Encrypt `plaintext` to bob's decrypt key and leave it in bob's inbox at the fake secret. */
async function deliverToBob(plaintext: string, kid?: string): Promise<string> {
  const key = (await bob.json<Key>('GET', '/key')).body
  const compact = await new CompactEncrypt(new TextEncoder().encode(plaintext))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: kid ?? key.kid })
    .encrypt(await importJWK(key.jwk as never, 'ECDH-ES'))
  const [protectedB64, , iv, ciphertext, tag] = compact.split('.')
  const id = `msg_in${String(++counter).padStart(20, '0')}_000`
  secret.inbox.set(id, {
    id, sub: await ps.sub(BOB, SECRET), from: 'mailto:alice@example.com', to: 'mailto:bob@example.com', kid: kid ?? key.kid,
    protected: protectedB64, iv, tag, blob: b64urlDecode(ciphertext), state: 'new',
  })
  return id
}

const path = (id: string, resource: string | null = SECRET) => `/messages/${id}${resource === null ? '' : `?resource=${encodeURIComponent(resource)}`}`

beforeAll(async () => {
  ps = await new FakePS().init()
  secret = new FakeSecret(ps)
  alice = await new Agent(ps, { handle: 'alice', email: 'alice@example.com' }, RESOURCE).init()
  bob = await new Agent(ps, BOB, RESOURCE).init()
  clearMetadataCache()
})

describe('getMessage', () => {
  it('OpenAPI lists getMessage with resource required', async () => {
    const spec = (await (await SELF.fetch(`${RESOURCE}/openapi.json`)).json()) as { paths: Record<string, Record<string, { operationId: string; parameters: Array<{ name: string; required: boolean }> }>> }
    const op = spec.paths['/messages/{id}'].get
    expect(op.operationId).toBe('getMessage')
    expect(op.parameters.find((p) => p.name === 'resource')?.required).toBe(true)
  })

  it('fetches over the chain, asks for JSON, and decrypts', async () => {
    const id = await deliverToBob(JSON.stringify({ text: 'hi bob' }))
    const { status, body } = await bob.json<Read>('GET', path(id))
    expect(status).toBe(200)
    expect(body).toMatchObject({ id, from: 'mailto:alice@example.com', to: 'mailto:bob@example.com', resource: SECRET, plaintext: { text: 'hi bob' }, warnings: [] })
    expect(secret.downloadAccepts.at(-1)).toBe('application/json')
    expect(secret.inbox.get(id)!.state).toBe('downloaded')
    expect(secret.seen.at(-1)).toBe(await ps.sub(BOB, SECRET))
    expect(decodeJwt(ps.lastAgentToken!).sub).toBe('aauth:read@decrypt.aauth.dev')
  })

  it('non-JSON plaintext comes back as text', async () => {
    const id = await deliverToBob('just text')
    const { body } = await bob.json<Read>('GET', path(id))
    expect(body.text).toBe('just text')
  })

  it('resource is required and must be an https origin', async () => {
    const id = await deliverToBob('x')
    for (const r of [null, 'http://secret.fake.test', `${SECRET}/`, `${SECRET}/messages`]) {
      const { status, body } = await bob.json<Refusal & { field: string }>('GET', path(id, r))
      expect(status).toBe(400)
      expect(body.field).toBe('resource')
    }
  })

  it("the messaging service's refusal passes through: alice cannot fetch bob's message", async () => {
    const id = await deliverToBob('for bob')
    const { status, body } = await alice.json<Refusal>('GET', path(id))
    expect(status).toBe(404)
    expect(body).toMatchObject({ error: 'not_found', step: 'get_message', resource: SECRET })
    expect(secret.inbox.get(id)!.state).toBe('new')
  })

  it('a kid decrypt does not hold is unknown_kid, with the message id', async () => {
    const id = await deliverToBob('x', 'not-a-kid')
    const { status, body } = await bob.json<Refusal & { id: string }>('GET', path(id))
    expect(status).toBe(404)
    expect(body).toMatchObject({ error: 'unknown_kid', id })
  })

  it('a chain the PS refuses is a 502 at step person_token', async () => {
    const id = await deliverToBob('x')
    ps.expectedIntermediary = 'https://someone-else.test'
    try {
      const { status, body } = await bob.json<Refusal>('GET', path(id))
      expect(status).toBe(502)
      expect(body).toMatchObject({ error: 'invalid_upstream_token', step: 'person_token' })
    } finally {
      ps.expectedIntermediary = undefined
    }
  })
})

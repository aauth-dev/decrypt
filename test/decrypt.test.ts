// decrypt.aauth.dev: keys per directed identity, decryptEnvelope in both
// body forms, refusals (tampered, wrong kid, other person), interop vectors
// from jose and jwcrypto decrypted by the Web Crypto implementation, and
// the 1 MiB timing check.
import { beforeAll, describe, expect, it } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { clearMetadataCache } from '@aauth/resource'
import { CompactEncrypt, importJWK } from 'jose'
import { Agent, FakePS, RESOURCE } from './fake-ps'
import { wrapPrivateJwk } from '../src/kek'
import joseVector from '../spec/vectors/jose.json'
import jwcryptoVector from '../spec/vectors/jwcrypto.json'

let ps: FakePS
let alice: Agent
let bob: Agent

interface Key { kid: string; alg: string; jwk: JsonWebKey; created_at: string }
interface Split { protected: string; iv: string; tag: string; ciphertext: string }

async function encryptTo(jwk: JsonWebKey, kid: string, plaintext: string | Uint8Array): Promise<Split> {
  const key = await importJWK(jwk as never, 'ECDH-ES')
  const compact = await new CompactEncrypt(typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext)
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid })
    .encrypt(key)
  const [protectedB64, , iv, ciphertext, tag] = compact.split('.')
  return { protected: protectedB64, iv, tag, ciphertext }
}

function b64urlDecode(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

beforeAll(async () => {
  ps = await new FakePS().init()
  alice = await new Agent(ps, { handle: 'alice', email: 'alice@example.com' }, RESOURCE).init()
  bob = await new Agent(ps, { handle: 'bob', email: 'bob@example.com' }, RESOURCE).init()
  clearMetadataCache()
})

describe('public surface', () => {
  it('well-known is person-token with the OpenAPI vocabulary', async () => {
    const meta = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)).json()) as Record<string, unknown>
    expect(meta.issuer).toBe(RESOURCE)
    expect(meta.access_mode).toBe('person-token')
  })
  it('unsigned GET /key is a person-token challenge', async () => {
    const res = await SELF.fetch(`${RESOURCE}/key`)
    expect(res.status).toBe(401)
    expect(res.headers.get('aauth-requirement')).toBe('requirement=person-token')
  })
  it('serves aauth-agent.json naming this origin and its JWKS (D24)', async () => {
    const doc = (await (await SELF.fetch(`${RESOURCE}/.well-known/aauth-agent.json`)).json()) as Record<string, unknown>
    expect(doc.issuer).toBe(RESOURCE)
    expect(doc.name).toBe(new URL(RESOURCE).host)
    expect(doc.jwks_uri).toBe(`${RESOURCE}/.well-known/jwks.json`)
    const jwks = (await (await SELF.fetch(doc.jwks_uri as string)).json()) as { keys: Array<Record<string, unknown>> }
    expect(jwks.keys[0].alg).toBe('Ed25519')
    expect(jwks.keys[0].kid).toBeTypeOf('string')
  })
  it('the retired host redirects pages and answers 404 on the API and well-known', async () => {
    const legacy = `https://${env.LEGACY_HOSTS!.split(/\s+/)[0]}`
    const page = await SELF.fetch(`${legacy}/`, { redirect: 'manual' })
    expect(page.status).toBe(301)
    expect(page.headers.get('location')).toBe(`${RESOURCE}/`)
    const llms = await SELF.fetch(`${legacy}/llms.txt`, { redirect: 'manual' })
    expect(llms.headers.get('location')).toBe(`${RESOURCE}/llms.txt`)
    for (const path of ['/key', '/.well-known/aauth-resource.json', '/openapi.json']) {
      const res = await SELF.fetch(`${legacy}${path}`)
      expect(res.status).toBe(404)
      expect(((await res.json()) as { error: string }).error).toBe('moved')
    }
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
  it('rotateKey mints a new current key and keeps the old one listed', async () => {
    const rotated = await alice.json<Key>('POST', '/key')
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

describe('decryptEnvelope', () => {
  const plaintext = JSON.stringify({ text: 'hi bob', attachments: [{ name: 'a.txt', media_type: 'text/plain', data: 'aGk=' }] })
  let bobKey: Key
  let split: Split
  beforeAll(async () => {
    bobKey = (await bob.json<Key>('GET', '/key')).body
    split = await encryptTo(bobKey.jwk, bobKey.kid, plaintext)
  })

  it('JSON form: returns the plaintext object', async () => {
    const { status, body } = await bob.json<{ kid: string; size: number; plaintext: unknown; warnings: string[] }>('POST', '/decrypt', { body: split })
    expect(status).toBe(200)
    expect(body.kid).toBe(bobKey.kid)
    expect(body.plaintext).toEqual(JSON.parse(plaintext))
    expect(body.warnings).toEqual([])
    expect(body.size).toBe(b64urlDecode(split.ciphertext).length)
  })
  it('octet-stream form with query parameters', async () => {
    const q = `?protected=${split.protected}&iv=${split.iv}&tag=${split.tag}`
    const { status, body } = await bob.json<{ plaintext: unknown }>('POST', `/decrypt${q}`, { body: b64urlDecode(split.ciphertext), contentType: 'application/octet-stream' })
    expect(status).toBe(200)
    expect(body.plaintext).toEqual(JSON.parse(plaintext))
  })
  it('an older key still decrypts after rotation', async () => {
    await bob.json('POST', '/key')
    const { status } = await bob.json('POST', '/decrypt', { body: split })
    expect(status).toBe(200)
  })
  it('non-JSON plaintext comes back as text', async () => {
    const s = await encryptTo(bobKey.jwk, bobKey.kid, 'just text')
    const { body } = await bob.json<{ text: string }>('POST', '/decrypt', { body: s })
    expect(body.text).toBe('just text')
  })
  it('tampered ciphertext is refused', async () => {
    const bytes = b64urlDecode(split.ciphertext)
    bytes[0] ^= 1
    const b64 = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const { status, body } = await bob.json<{ error: string }>('POST', '/decrypt', { body: { ...split, ciphertext: b64 } })
    expect(status).toBe(400)
    expect(body.error).toBe('decrypt_failed')
  })
  it('a tampered protected header (AAD) is refused', async () => {
    const h = JSON.parse(new TextDecoder().decode(b64urlDecode(split.protected))) as Record<string, unknown>
    h.x = 1
    const protectedB64 = btoa(JSON.stringify(h)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const { status, body } = await bob.json<{ error: string }>('POST', '/decrypt', { body: { ...split, protected: protectedB64 } })
    expect(status).toBe(400)
    expect(body.error).toBe('decrypt_failed')
  })
  it('wrong kid is unknown_kid', async () => {
    const s = await encryptTo(bobKey.jwk, 'nope', plaintext)
    const { status, body } = await bob.json<{ error: string }>('POST', '/decrypt', { body: s })
    expect(status).toBe(404)
    expect(body.error).toBe('unknown_kid')
  })
  it("another person's token cannot use bob's key", async () => {
    const { status, body } = await alice.json<{ error: string }>('POST', '/decrypt', { body: split })
    expect(status).toBe(404)
    expect(body.error).toBe('unknown_kid')
  })
  it('a non ECDH-ES header is refused before any key lookup', async () => {
    const protectedB64 = btoa(JSON.stringify({ alg: 'RSA-OAEP', enc: 'A256GCM', kid: bobKey.kid })).replace(/=+$/, '')
    const { status, body } = await bob.json<{ error: string }>('POST', '/decrypt', { body: { ...split, protected: protectedB64 } })
    expect(status).toBe(400)
    expect(body.error).toBe('unsupported_alg')
  })
})

describe('interop vectors (spec/vectors)', () => {
  // Load each vector's private key under Alice's identity, then decrypt.
  for (const vector of [joseVector, jwcryptoVector]) {
    it(`decrypts the ${vector.generator} vector`, async () => {
      const iss = ps.iss
      const sub = await ps.sub({ handle: 'alice', email: 'alice@example.com' }, RESOURCE)
      const wrapped = await wrapPrivateJwk(env.KEK, iss, sub, vector.kid, vector.private_jwk as JsonWebKey)
      await env.DB.prepare('INSERT OR REPLACE INTO private_keys (ps_iss, ps_sub, kid, alg, private_jwk, public_jwk, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(iss, sub, vector.kid, 'ECDH-ES', wrapped, JSON.stringify(vector.public_jwk), new Date().toISOString())
        .run()
      const { status, body } = await alice.json<{ plaintext: unknown; kid: string }>('POST', '/decrypt', {
        body: { protected: vector.protected, iv: vector.iv, tag: vector.tag, ciphertext: vector.ciphertext },
      })
      expect(status).toBe(200)
      expect(body.kid).toBe(vector.kid)
      expect(body.plaintext).toEqual(JSON.parse(vector.plaintext))
    })
  }
})

describe('timing', () => {
  it('decrypts 1 MiB and reports the wall time', async () => {
    const key = (await alice.json<Key>('GET', '/key')).body
    const big = new Uint8Array(1_048_576 - 16)
    for (let o = 0; o < big.length; o += 65536) crypto.getRandomValues(big.subarray(o, Math.min(o + 65536, big.length)))
    const s = await encryptTo(key.jwk, key.kid, big)
    const t0 = performance.now()
    const res = await alice.call('POST', `/decrypt?protected=${s.protected}&iv=${s.iv}&tag=${s.tag}`, { body: b64urlDecode(s.ciphertext), contentType: 'application/octet-stream' })
    const ms = performance.now() - t0
    expect(res.status).toBe(200)
    const body = (await res.json()) as { size: number; text: string }
    expect(body.size).toBe(big.length)
    console.log(`TIMING 1 MiB decrypt round trip: ${ms.toFixed(1)} ms wall (includes signature verify and response JSON)`)
  })
  it('refuses ciphertext over 1 MiB', async () => {
    const key = (await alice.json<Key>('GET', '/key')).body
    const s = await encryptTo(key.jwk, key.kid, new Uint8Array(1_048_577))
    const res = await alice.call('POST', `/decrypt?protected=${s.protected}&iv=${s.iv}&tag=${s.tag}`, { body: b64urlDecode(s.ciphertext), contentType: 'application/octet-stream' })
    expect(res.status).toBe(413)
  })
})

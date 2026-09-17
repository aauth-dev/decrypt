// spec/container.md against its vectors: the compact JWEs from jose and
// jwcrypto decrypted by the Web Crypto implementation in src/jwe.ts, which
// shares no code with either generator; and what parseCompact refuses.
import { describe, expect, it } from 'vitest'
import { decryptCompact, JweError, parseCompact } from '../src/jwe'
import joseVector from '../spec/vectors/jose.json'
import jwcryptoVector from '../spec/vectors/jwcrypto.json'

describe('interop vectors (spec/vectors)', () => {
  for (const vector of [joseVector, jwcryptoVector]) {
    it(`decrypts the ${vector.generator} compact JWE`, async () => {
      const { plaintext, header } = await decryptCompact(vector.private_jwk as JsonWebKey, vector.compact)
      expect(new TextDecoder().decode(plaintext)).toBe(vector.plaintext)
      expect(JSON.parse(vector.plaintext)).toEqual({ text: expect.any(String) })
      expect(header.kid).toBe(vector.kid)
      expect(header).toMatchObject({ alg: 'ECDH-ES', enc: 'A256GCM' })
    })
    it(`the ${vector.generator} vector is five parts with an empty encrypted key`, () => {
      const parts = vector.compact.split('.')
      expect(parts).toHaveLength(5)
      expect(parts[1]).toBe('')
    })
  }
})

describe('parseCompact', () => {
  const code = (fn: () => unknown) => {
    try {
      fn()
    } catch (err) {
      return err instanceof JweError ? err.code : String(err)
    }
    return 'ok'
  }
  const [p, , iv, ct, tag] = joseVector.compact.split('.')
  it('refuses anything that is not five parts with an empty second', () => {
    expect(code(() => parseCompact(undefined))).toBe('invalid_jwe')
    expect(code(() => parseCompact({ protected: p }))).toBe('invalid_jwe')
    expect(code(() => parseCompact(`${p}.${iv}.${ct}.${tag}`))).toBe('invalid_jwe')
    expect(code(() => parseCompact(`${p}.a2V5.${iv}.${ct}.${tag}`))).toBe('invalid_jwe')
    expect(code(() => parseCompact(`${p}..${iv}..${tag}`))).toBe('invalid_jwe')
    expect(code(() => parseCompact(`${p}..${iv}.${ct}+.${tag}`))).toBe('invalid_jwe')
    expect(code(() => parseCompact(joseVector.compact))).toBe('ok')
  })
  it('a part altered after encryption fails authentication', async () => {
    const flipped = ct.slice(0, -1) + (ct.endsWith('A') ? 'B' : 'A')
    await expect(decryptCompact(joseVector.private_jwk as JsonWebKey, `${p}..${iv}.${flipped}.${tag}`)).rejects.toMatchObject({ code: 'decrypt_failed' })
  })
})

// Interop vector from jose (Node): encrypt the sample plaintext to a fresh
// P-256 key as JWE ECDH-ES A256GCM, split the compact form into the
// disassembled container, and write spec/vectors/jose.json.
import { writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { generateKeyPair, exportJWK, CompactEncrypt } from 'jose'

const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true })
const pub = await exportJWK(publicKey)
const priv = await exportJWK(privateKey)
const kid = createHash('sha256').update(JSON.stringify({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y })).digest('base64url')

const plaintext = JSON.stringify({
  text: 'Hello from jose. The quick brown fox jumps over the lazy dog.',
  attachments: [{ name: 'hello.txt', media_type: 'text/plain', data: Buffer.from('attachment bytes\n').toString('base64') }],
})

const compact = await new CompactEncrypt(new TextEncoder().encode(plaintext))
  .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid })
  .encrypt(publicKey)
const [protectedB64, encryptedKey, iv, ciphertext, tag] = compact.split('.')
if (encryptedKey !== '') throw new Error('ECDH-ES direct key agreement has no encrypted key')

const vector = {
  generator: 'jose (Node)',
  alg: 'ECDH-ES', enc: 'A256GCM', crv: 'P-256',
  kid,
  private_jwk: { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y, d: priv.d },
  public_jwk: { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y },
  plaintext,
  protected: protectedB64,
  protected_header: JSON.parse(Buffer.from(protectedB64, 'base64url').toString()),
  iv, ciphertext, tag,
  compact,
}
writeFileSync(new URL('../spec/vectors/jose.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n')
console.log('wrote spec/vectors/jose.json', kid)

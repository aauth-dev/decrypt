// Private keys at rest: AES-256-GCM under the KEK secret, with the row's
// identity and kid as AAD so a wrapped key cannot be moved between rows.
import { b64urlDecode, b64urlEncode } from './util'

async function kekKey(kekB64url: string): Promise<CryptoKey> {
  const raw = b64urlDecode(kekB64url)
  if (raw.length !== 32) throw new Error('KEK must be 32 bytes base64url')
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

const aad = (iss: string, sub: string, kid: string) => new TextEncoder().encode(`${iss}|${sub}|${kid}`)

export async function wrapPrivateJwk(kek: string, iss: string, sub: string, kid: string, jwk: JsonWebKey): Promise<string> {
  const key = await kekKey(kek)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(iss, sub, kid) }, key, new TextEncoder().encode(JSON.stringify(jwk)))
  return `${b64urlEncode(iv)}.${b64urlEncode(new Uint8Array(ct))}`
}

export async function unwrapPrivateJwk(kek: string, iss: string, sub: string, kid: string, wrapped: string): Promise<JsonWebKey> {
  const key = await kekKey(kek)
  const [ivB64, ctB64] = wrapped.split('.')
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlDecode(ivB64), additionalData: aad(iss, sub, kid) }, key, b64urlDecode(ctB64))
  return JSON.parse(new TextDecoder().decode(pt)) as JsonWebKey
}

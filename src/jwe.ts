// JWE ECDH-ES + A256GCM on P-256, disassembled (plan D18, D19), on Web
// Crypto directly: ECDH → Concat KDF (RFC 7518 §4.6.2) → AES-256-GCM with
// the base64url protected header as AAD. No library, so decrypting the
// jose and jwcrypto vectors is a cross-implementation check.
import { b64urlDecode } from './util'

export interface Envelope {
  /** base64url protected header, verbatim (it is the AAD) */
  protected: string
  iv: string
  tag: string
  ciphertext: Uint8Array
}

export interface ProtectedHeader {
  alg: 'ECDH-ES'
  enc: 'A256GCM'
  kid: string
  epk: JsonWebKey
  apu?: string
  apv?: string
  [k: string]: unknown
}

export class JweError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
  }
}

export function parseProtectedHeader(protectedB64: string): ProtectedHeader {
  let h: Record<string, unknown>
  try {
    h = JSON.parse(new TextDecoder().decode(b64urlDecode(protectedB64))) as Record<string, unknown>
  } catch {
    throw new JweError('invalid_protected_header', 'protected header is not base64url JSON')
  }
  if (h.alg !== 'ECDH-ES') throw new JweError('unsupported_alg', `alg must be ECDH-ES, got ${String(h.alg)}`)
  if (h.enc !== 'A256GCM') throw new JweError('unsupported_enc', `enc must be A256GCM, got ${String(h.enc)}`)
  if (typeof h.kid !== 'string' || !h.kid) throw new JweError('missing_kid', 'protected header has no kid')
  const epk = h.epk as JsonWebKey | undefined
  if (!epk || epk.kty !== 'EC' || epk.crv !== 'P-256' || typeof epk.x !== 'string' || typeof epk.y !== 'string') {
    throw new JweError('invalid_epk', 'epk must be an EC P-256 public JWK')
  }
  for (const f of ['apu', 'apv'] as const) {
    if (h[f] !== undefined && typeof h[f] !== 'string') throw new JweError('invalid_protected_header', `${f} must be a string`)
  }
  return h as unknown as ProtectedHeader
}

function lenPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length)
  new DataView(out.buffer).setUint32(0, bytes.length)
  out.set(bytes, 4)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Concat KDF, one round (keydatalen 256 fits one SHA-256 block of output). */
async function concatKdf(z: Uint8Array, header: ProtectedHeader): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const otherInfo = concat(
    lenPrefixed(enc.encode(header.enc)),
    lenPrefixed(header.apu ? b64urlDecode(header.apu) : new Uint8Array(0)),
    lenPrefixed(header.apv ? b64urlDecode(header.apv) : new Uint8Array(0)),
    new Uint8Array([0, 0, 1, 0]), // keydatalen = 256 bits
  )
  const round = concat(new Uint8Array([0, 0, 0, 1]), z, otherInfo)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', round as BufferSource))
}

export async function importPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  const { alg: _a, key_ops: _k, ext: _e, use: _u, ...k } = jwk as JsonWebKey & { alg?: string; use?: string }
  return crypto.subtle.importKey('jwk', k, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
}

export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  const { alg: _a, key_ops: _k, ext: _e, use: _u, d: _d, ...k } = jwk as JsonWebKey & { alg?: string; use?: string }
  return crypto.subtle.importKey('jwk', k, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
}

/** Decrypt a disassembled JWE with the recipient's private key. */
export async function decryptEnvelope(privateJwk: JsonWebKey, env: Envelope): Promise<{ plaintext: Uint8Array; header: ProtectedHeader }> {
  const header = parseProtectedHeader(env.protected)
  const iv = b64urlDecode(env.iv)
  const tag = b64urlDecode(env.tag)
  if (iv.length !== 12) throw new JweError('invalid_iv', 'iv must be 12 bytes')
  if (tag.length !== 16) throw new JweError('invalid_tag', 'tag must be 16 bytes')

  let epk: CryptoKey
  try {
    epk = await importPublicKey(header.epk)
  } catch {
    throw new JweError('invalid_epk', 'epk did not import as a P-256 public key')
  }
  const priv = await importPrivateKey(privateJwk)
  const z = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: epk } as never, priv, 256))
  const cek = await crypto.subtle.importKey('raw', await concatKdf(z, header), { name: 'AES-GCM' }, false, ['decrypt'])
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(env.protected), tagLength: 128 },
      cek,
      concat(env.ciphertext, tag),
    )
    return { plaintext: new Uint8Array(pt), header }
  } catch {
    throw new JweError('decrypt_failed', 'authentication failed: wrong key, tampered ciphertext, or tampered header')
  }
}

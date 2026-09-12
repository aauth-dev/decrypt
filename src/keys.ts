// Key lifecycle: mint P-256, wrap, store, list, load for decrypt.
import type { Env, KeyRow } from './types'
import { wrapPrivateJwk, unwrapPrivateJwk } from './kek'
import { ecThumbprint, nowIso } from './util'

export const ALG = 'ECDH-ES'

export interface PublicKeyRecord {
  kid: string
  alg: string
  jwk: JsonWebKey
  created_at: string
  retired_at?: string | null
}

export function publicRecord(row: KeyRow): PublicKeyRecord {
  return { kid: row.kid, alg: row.alg, jwk: JSON.parse(row.public_jwk) as JsonWebKey, created_at: row.created_at, ...(row.retired_at ? { retired_at: row.retired_at } : {}) }
}

export async function mintKey(env: Env, iss: string, sub: string): Promise<KeyRow> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
  const priv = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey & { key_ops?: string[]; ext?: boolean }
  const { d: _d, key_ops: _ko, ext: _ext, ...pubRest } = priv
  const pub: JsonWebKey = { kty: 'EC', crv: 'P-256', x: pubRest.x, y: pubRest.y }
  const kid = await ecThumbprint(pub)
  const privateJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y, d: priv.d }
  const wrapped = await wrapPrivateJwk(env.KEK, iss, sub, kid, privateJwk)
  const now = nowIso()
  await env.DB.prepare(
    'INSERT INTO private_keys (ps_iss, ps_sub, kid, alg, private_jwk, public_jwk, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(iss, sub, kid, ALG, wrapped, JSON.stringify(pub), now)
    .run()
  return { ps_iss: iss, ps_sub: sub, kid, alg: ALG, private_jwk: wrapped, public_jwk: JSON.stringify(pub), created_at: now, retired_at: null, purge_after: null }
}

export async function currentKey(env: Env, iss: string, sub: string): Promise<KeyRow | null> {
  return env.DB.prepare('SELECT * FROM private_keys WHERE ps_iss = ? AND ps_sub = ? AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1')
    .bind(iss, sub)
    .first<KeyRow>()
}

export async function listKeys(env: Env, iss: string, sub: string): Promise<KeyRow[]> {
  const r = await env.DB.prepare('SELECT * FROM private_keys WHERE ps_iss = ? AND ps_sub = ? ORDER BY created_at DESC').bind(iss, sub).all<KeyRow>()
  return r.results
}

export async function loadPrivateJwk(env: Env, iss: string, sub: string, kid: string): Promise<{ row: KeyRow; jwk: JsonWebKey } | null> {
  const row = await env.DB.prepare('SELECT * FROM private_keys WHERE ps_iss = ? AND ps_sub = ? AND kid = ?').bind(iss, sub, kid).first<KeyRow>()
  if (!row) return null
  return { row, jwk: await unwrapPrivateJwk(env.KEK, iss, sub, kid, row.private_jwk) }
}

// Reading a message: the decrypt step both routes share, and getMessage
// (D1), the chained download. The caller names the messaging service in
// `resource` and the message id; decrypt obtains a person token for that
// service over the chain (chain.ts), fetches the envelope in its JSON form,
// and decrypts it with the caller's key. The ciphertext never passes
// through the agent. Nothing here names a messaging service.
//
//   1. path id, query resource (an https origin).
//   2. person token for `resource` over the chain.
//   3. GET {resource}/messages/{id}, Accept: application/json. Refusals
//      pass through; a system message comes back as it is, with nothing
//      to decrypt.
//   4. decrypt {protected, iv, tag, blob} as decryptEnvelope does.
//   5. {id, from, to, resource, kid, size, plaintext | text, warnings}.
import type { Context } from 'hono'
import { chainedFetch, passThrough } from './chain'
import { emit } from './events'
import { decryptEnvelope, JweError, parseProtectedHeader } from './jwe'
import { loadPrivateJwk } from './keys'
import type { HonoEnv } from './types'
import { B64URL_RE, b64urlDecode, identityHash } from './util'

export const MAX_CIPHERTEXT = 1_048_576
const MESSAGE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/

export interface Envelope {
  protected: string
  iv: string
  tag: string
  ciphertext: Uint8Array
}

/** An https origin, exactly: no path, query, fragment, or trailing slash. Same rule as encrypt. */
export function parseResource(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > 253 + 8) return null
  let u: URL
  try {
    u = new URL(input)
  } catch {
    return null
  }
  if (u.protocol !== 'https:' || u.username || u.password) return null
  if (u.origin !== input) return null
  return u.origin
}

/**
 * Decrypt a validated envelope with the caller's key and answer. `extra`
 * leads the response body (getMessage puts the message id and addresses
 * there); `fetchedBy` goes on the event.
 */
export async function answerDecrypted(c: Context<HonoEnv>, env: Envelope, fetchedBy: 'agent' | 'decrypt', extra: Record<string, unknown> = {}): Promise<Response> {
  const id = c.get('identity')
  const started = Date.now()
  if (env.ciphertext.byteLength === 0) return c.json({ error: 'invalid_request', field: 'ciphertext', detail: 'empty' }, 400)
  if (env.ciphertext.byteLength > MAX_CIPHERTEXT) return c.json({ error: 'payload_too_large', detail: `ciphertext is limited to ${MAX_CIPHERTEXT} bytes` }, 413)

  let header
  try {
    header = parseProtectedHeader(env.protected)
  } catch (err) {
    if (err instanceof JweError) {
      emit(c, { event: 'decrypt_refused', level: 40, code: err.code })
      return c.json({ ...extra, error: err.code, detail: err.message }, 400)
    }
    throw err
  }
  const key = await loadPrivateJwk(c.env, id.iss, id.sub, header.kid)
  if (!key) {
    emit(c, { event: 'decrypt_refused', level: 40, code: 'unknown_kid', identity: await identityHash(id.iss, id.sub) })
    return c.json({ ...extra, error: 'unknown_kid', detail: 'no key of yours matches the kid in the protected header' }, 404)
  }
  try {
    const { plaintext } = await decryptEnvelope(key.jwk, { protected: env.protected, iv: env.iv, tag: env.tag, ciphertext: env.ciphertext })
    const text = new TextDecoder().decode(plaintext)
    let obj: unknown = null
    try {
      obj = JSON.parse(text)
    } catch {
      obj = null
    }
    emit(c, {
      event: 'message_decrypted', identity: await identityHash(id.iss, id.sub), kid: header.kid, size: env.ciphertext.byteLength, ms: Date.now() - started, fetched_by: fetchedBy,
    })
    const warnings: string[] = []
    return c.json(
      obj && typeof obj === 'object' && !Array.isArray(obj)
        ? { ...extra, kid: header.kid, size: env.ciphertext.byteLength, plaintext: obj, warnings }
        : { ...extra, kid: header.kid, size: env.ciphertext.byteLength, text, warnings },
    )
  } catch (err) {
    if (err instanceof JweError) {
      emit(c, { event: 'decrypt_refused', level: 40, code: err.code, kid: header.kid })
      return c.json({ ...extra, error: err.code, detail: err.message }, 400)
    }
    throw err
  }
}

export async function getMessage(c: Context<HonoEnv>): Promise<Response> {
  const id = c.get('identity')
  const who = await identityHash(id.iss, id.sub)

  // ── 1. the request ──
  const messageId = c.req.param('id') ?? ''
  if (!MESSAGE_ID_RE.test(messageId)) return c.json({ error: 'invalid_request', field: 'id', detail: 'the message id from your messaging service (getMessages)' }, 400)
  const resource = parseResource(c.req.query('resource'))
  if (!resource) return c.json({ error: 'invalid_request', field: 'resource', detail: 'the messaging service holding the message, as an https origin (see llms.txt for the default)' }, 400)

  // ── 2. person token for the resource ──
  const chain = await chainedFetch(c.env, id.jwt, resource)
  if (!chain.ok) {
    emit(c, { event: 'chain_failed', level: 40, step: 'person_token', code: chain.error, detail: chain.detail, ps: id.iss, resource, identity: who })
    return c.json({ error: chain.error, detail: `no person token for ${resource} from ${id.iss}: ${chain.detail}`, step: 'person_token' }, 502)
  }
  emit(c, { event: 'chain_person_token', ok: true, ps: id.iss, resource, identity: who })

  // ── 3. the envelope ──
  let res: Response
  try {
    res = await chain.fetch(`${resource}/messages/${encodeURIComponent(messageId)}`, { method: 'GET', headers: { accept: 'application/json' } })
  } catch (err) {
    emit(c, { event: 'chain_failed', level: 40, step: 'get_message', code: 'resource_unreachable', detail: String(err), resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer: ${String(err)}`, step: 'get_message' }, 502)
  }
  if (res.status !== 200) {
    const refusal = await passThrough(res)
    emit(c, { event: 'download_refused', code: refusal.error, step: 'get_message', status: res.status, resource, identity: who })
    // A 401 from the messaging service is about decrypt's chained token, not the caller's: do not challenge the caller.
    const status = res.status === 401 ? 502 : res.status
    return c.json({ ...refusal, step: 'get_message', resource }, status as 404)
  }
  let body: Record<string, unknown>
  try {
    body = (await res.json()) as Record<string, unknown>
  } catch {
    return c.json({ error: 'invalid_response', detail: `${resource} answered getMessage without JSON`, step: 'get_message' }, 502)
  }
  const extra = { id: body.id ?? messageId, from: body.from, to: body.to, resource }
  if (body.system !== undefined) return c.json({ ...body, resource, warnings: [] })
  for (const f of ['protected', 'iv', 'tag', 'blob'] as const) {
    const v = body[f]
    if (typeof v !== 'string' || !B64URL_RE.test(v)) return c.json({ ...extra, error: 'invalid_response', detail: `${resource} answered getMessage without a base64url ${f}`, step: 'get_message' }, 502)
  }

  // ── 4, 5. decrypt ──
  return answerDecrypted(c, { protected: body.protected as string, iv: body.iv as string, tag: body.tag as string, ciphertext: b64urlDecode(body.blob as string) }, 'decrypt', extra)
}

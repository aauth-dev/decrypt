// readMessage (D27, section 7b): the one call to read. The caller names
// the message id and, optionally, the messaging service in `resource`
// (default DEFAULT_RESOURCE, Q7); this service obtains a person token for it
// over the chain (chain.ts), downloads the message as a compact JWE, and
// decrypts it with the caller's private key for the JWE's kid. Neither the
// JWE nor a key passes through the agent. Nothing here names a messaging
// service.
//
//   1. person token for `resource` over the chain.
//   2. downloadMessage {id}: GET {resource}/messages/{id} with
//      Accept: application/json. Refusals pass through with
//      step: download_message; a system message comes back as it is, with
//      nothing to decrypt.
//   3. decrypt with the private key for the JWE kid; return `text`.
import type { Context } from 'hono'
import { parseJsonBody } from './auth'
import { chainedFetch, passThrough } from './chain'
import { emit } from './events'
import { decryptEnvelope, JweError, parseCompact, parseProtectedHeader } from './jwe'
import { loadPrivateJwk } from './keys'
import type { HonoEnv } from './types'
import { identityHash } from './util'

const MESSAGE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/

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

/** `resource` from a request body, or the default when it is absent. */
export function resourceOf(defaultResource: string, input: unknown): string | null {
  return input === undefined ? parseResource(defaultResource) : parseResource(input)
}

export async function readMessage(c: Context<HonoEnv>): Promise<Response> {
  const id = c.get('identity')
  const who = await identityHash(id.iss, id.sub)
  const started = Date.now()

  // ── the request ──
  const body = parseJsonBody<{ id?: unknown; resource?: unknown }>(c)
  if (!body) return c.json({ error: 'invalid_json' }, 400)
  const messageId = typeof body.id === 'string' ? body.id : ''
  if (!MESSAGE_ID_RE.test(messageId)) return c.json({ error: 'invalid_request', field: 'id', detail: 'the message id from listMessages at your messaging service' }, 400)
  const resource = resourceOf(c.env.DEFAULT_RESOURCE, body.resource)
  if (!resource) return c.json({ error: 'invalid_request', field: 'resource', detail: 'the messaging service holding the message, as an https origin; leave it out for the default' }, 400)

  // ── 1. person token for the resource ──
  const chain = await chainedFetch(c.env, id.jwt, resource)
  if (!chain.ok) {
    emit(c, { event: 'chain_failed', level: 40, step: 'person_token', code: chain.error, detail: chain.detail, ps: id.iss, resource, identity: who })
    return c.json({ error: chain.error, detail: `no person token for ${resource} from ${id.iss}: ${chain.detail}`, step: 'person_token', resource }, 502)
  }
  emit(c, { event: 'chain_person_token', ok: true, ps: id.iss, resource, identity: who })

  // ── 2. downloadMessage ──
  let res: Response
  try {
    res = await chain.fetch(`${resource}/messages/${encodeURIComponent(messageId)}`, { method: 'GET', headers: { accept: 'application/json' } })
  } catch (err) {
    emit(c, { event: 'chain_failed', level: 40, step: 'download_message', code: 'resource_unreachable', detail: String(err), resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer: ${String(err)}`, step: 'download_message', resource }, 502)
  }
  if (res.status !== 200) {
    const refusal = await passThrough(res)
    emit(c, { event: 'download_refused', code: refusal.error, step: 'download_message', status: res.status, resource, identity: who })
    // A 401 from the messaging service is about this service's chained token, not the caller's: do not challenge the caller.
    return c.json({ ...refusal, step: 'download_message', resource }, (res.status === 401 ? 502 : res.status) as 404)
  }
  let message: Record<string, unknown>
  try {
    message = (await res.json()) as Record<string, unknown>
  } catch {
    return c.json({ error: 'invalid_response', detail: `${resource} answered downloadMessage without JSON`, step: 'download_message', resource }, 502)
  }
  if (message.system !== undefined) return c.json({ ...message, resource, warnings: [] })
  const about = { id: message.id ?? messageId, from: message.from, ...(message.from_name !== undefined ? { from_name: message.from_name } : {}), to: message.to, created_at: message.created_at, resource }

  // ── 3. decrypt ──
  let envelope
  let header
  try {
    envelope = parseCompact(message.jwe)
    header = parseProtectedHeader(envelope.protected)
  } catch (err) {
    if (!(err instanceof JweError)) throw err
    emit(c, { event: 'decrypt_refused', level: 40, code: err.code, resource, identity: who })
    return c.json({ ...about, error: 'invalid_jwe', detail: `${resource} answered downloadMessage with something that is not a compact JWE: ${err.message}`, step: 'download_message' }, 502)
  }
  const key = await loadPrivateJwk(c.env, id.iss, id.sub, header.kid)
  if (!key) {
    emit(c, { event: 'decrypt_refused', level: 40, code: 'unknown_kid', identity: who })
    return c.json({ ...about, kid: header.kid, error: 'unknown_kid', detail: 'no private key of yours here matches the JWE kid; if you changed read service, read this message at the one in its read_message_with' }, 404)
  }
  let plaintext: Uint8Array
  try {
    plaintext = (await decryptEnvelope(key.jwk, envelope)).plaintext
  } catch (err) {
    if (!(err instanceof JweError)) throw err
    emit(c, { event: 'decrypt_refused', level: 40, code: err.code, kid: header.kid, identity: who })
    return c.json({ ...about, kid: header.kid, error: err.code, detail: err.message }, 422)
  }
  const raw = new TextDecoder().decode(plaintext)
  const warnings: string[] = []
  let text = raw
  try {
    const obj = JSON.parse(raw) as unknown
    if (obj && typeof obj === 'object' && !Array.isArray(obj) && typeof (obj as { text?: unknown }).text === 'string') text = (obj as { text: string }).text
    else warnings.push('plaintext_not_json')
  } catch {
    warnings.push('plaintext_not_json')
  }
  emit(c, { event: 'message_read', identity: who, kid: header.kid, size: typeof message.jwe === 'string' ? message.jwe.length : undefined, ms: Date.now() - started, resource })
  return c.json({ ...about, kid: header.kid, text, warnings })
}

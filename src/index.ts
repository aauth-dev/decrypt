// decrypt.aauth.dev — the decrypt Worker (plan A4, A5, D26). Public:
// well-known (resource and agent), JWKS, OpenAPI, pages. Protected (person
// token): getKey, rotateKey, getKeys, decryptEnvelope.
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { requireIdentity, parseJsonBody } from './auth'
import { getPublicJWK } from './crypto'
import { emit, emitBackground } from './events'
import { decryptEnvelope, JweError, parseProtectedHeader } from './jwe'
import { currentKey, listKeys, loadPrivateJwk, mintKey, publicRecord } from './keys'
import { openapi } from './openapi'
import type { Env, HonoEnv } from './types'
import { B64URL_RE, b64urlDecode, identityHash, nowIso } from './util'

const MAX_CIPHERTEXT = 1_048_576

const app = new Hono<HonoEnv>()

app.onError((err, c) => {
  const error = err instanceof Error ? err : new Error(String(err))
  console.error('unhandled_error', error.stack ?? String(error))
  emit(c, { event: 'unhandled_error', level: 50, msg: error.message, error_name: error.name, error_stack: error.stack })
  return c.json({ error: 'internal_error' }, 500)
})

app.use('*', cors({ origin: '*', exposeHeaders: ['AAuth-Requirement', 'Signature-Error', 'Accept-Signature', 'Accept-Signature-Scheme', 'Accept-Signature-Alg'] }))

// A retired host (decrypt.agent.coop for one release after the move to
// decrypt.aauth.dev): pages redirect to the new origin, the API and the
// well-known documents answer 404 so no agent keeps a stale issuer.
app.use('*', async (c, next) => {
  const legacy = (c.env.LEGACY_HOSTS ?? '').split(/\s+/).filter(Boolean)
  const url = new URL(c.req.url)
  if (!legacy.includes(url.host)) return next()
  const isPage = c.req.method === 'GET' && (url.pathname === '/' || /^\/(privacy|llms\.txt|robots\.txt|sitemap\.xml)$/.test(url.pathname))
  if (isPage) return c.redirect(`${c.env.ORIGIN}${url.pathname}`, 301)
  emit(c, { event: 'legacy_host_refused', level: 40, host: url.host })
  return c.json({ error: 'moved', detail: `this service is now ${c.env.ORIGIN}; connect to it there` }, 404)
})

app.get('/.well-known/aauth-resource.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    name: 'decrypt.aauth.dev',
    description: 'Holds the private key that decrypts your end-to-end encrypted messages and decrypts them for your agent. The default decrypt service for secret.agent.coop; the code is open and you can run your own.',
    access_mode: 'person-token',
    r3_vocabularies: { 'urn:aauth:vocabulary:openapi': `${origin}/openapi.json` },
    contact: { feedback: 'feedback@agent.coop', abuse: 'abuse@agent.coop' },
    llms_txt: `${origin}/llms.txt`,
  })
})
// D24: decrypt will act as an intermediary toward the messaging service for
// the chained download. The agent document names it and points at the JWKS
// the agent token is signed under.
app.get('/.well-known/aauth-agent.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({ issuer: origin, name: new URL(origin).host, jwks_uri: `${origin}/.well-known/jwks.json` })
})
app.get('/.well-known/jwks.json', async (c) => c.json({ keys: [await getPublicJWK(c.env.SIGNING_KEY)] }))
app.get('/openapi.json', (c) => c.json(openapi(c.env.ORIGIN)))
app.get('/health', (c) => c.json({ status: 'ok', service: c.env.SERVICE }))

app.get('/key', requireIdentity, async (c) => {
  const id = c.get('identity')
  let row = await currentKey(c.env, id.iss, id.sub)
  if (!row) {
    row = await mintKey(c.env, id.iss, id.sub)
    emit(c, { event: 'key_created', identity: await identityHash(id.iss, id.sub), kid: row.kid })
  }
  return c.json(publicRecord(row))
})

app.post('/key', requireIdentity, async (c) => {
  const id = c.get('identity')
  const row = await mintKey(c.env, id.iss, id.sub)
  emit(c, { event: 'key_rotated', identity: await identityHash(id.iss, id.sub), kid: row.kid })
  return c.json(publicRecord(row))
})

app.get('/keys', requireIdentity, async (c) => {
  const id = c.get('identity')
  const rows = await listKeys(c.env, id.iss, id.sub)
  return c.json({ keys: rows.map(publicRecord) })
})

app.post('/decrypt', requireIdentity, async (c) => {
  const id = c.get('identity')
  const started = Date.now()
  const ct = c.req.header('content-type') ?? ''
  let protectedB64: string | undefined
  let iv: string | undefined
  let tag: string | undefined
  let ciphertext: Uint8Array | undefined
  if (ct.startsWith('application/json')) {
    const body = parseJsonBody<{ protected?: unknown; iv?: unknown; tag?: unknown; ciphertext?: unknown }>(c)
    if (!body) return c.json({ error: 'invalid_json' }, 400)
    protectedB64 = typeof body.protected === 'string' ? body.protected : undefined
    iv = typeof body.iv === 'string' ? body.iv : undefined
    tag = typeof body.tag === 'string' ? body.tag : undefined
    if (typeof body.ciphertext !== 'string' || !B64URL_RE.test(body.ciphertext)) return c.json({ error: 'invalid_request', field: 'ciphertext', detail: 'base64url string required' }, 400)
    ciphertext = b64urlDecode(body.ciphertext)
  } else {
    protectedB64 = c.req.query('protected') ?? c.req.header('x-jwe-protected') ?? undefined
    iv = c.req.query('iv') ?? c.req.header('x-jwe-iv') ?? undefined
    tag = c.req.query('tag') ?? c.req.header('x-jwe-tag') ?? undefined
    ciphertext = c.get('rawBody')
  }
  for (const [name, v] of [['protected', protectedB64], ['iv', iv], ['tag', tag]] as const) {
    if (!v || !B64URL_RE.test(v)) return c.json({ error: 'invalid_request', field: name, detail: 'base64url string required' }, 400)
  }
  if (!ciphertext || ciphertext.byteLength === 0) return c.json({ error: 'invalid_request', field: 'ciphertext', detail: 'empty' }, 400)
  if (ciphertext.byteLength > MAX_CIPHERTEXT) return c.json({ error: 'payload_too_large', detail: `ciphertext is limited to ${MAX_CIPHERTEXT} bytes` }, 413)

  let header
  try {
    header = parseProtectedHeader(protectedB64!)
  } catch (err) {
    if (err instanceof JweError) {
      emit(c, { event: 'decrypt_refused', level: 40, code: err.code })
      return c.json({ error: err.code, detail: err.message }, 400)
    }
    throw err
  }
  const key = await loadPrivateJwk(c.env, id.iss, id.sub, header.kid)
  if (!key) {
    emit(c, { event: 'decrypt_refused', level: 40, code: 'unknown_kid', identity: await identityHash(id.iss, id.sub) })
    return c.json({ error: 'unknown_kid', detail: 'no key of yours matches the kid in the protected header' }, 404)
  }
  try {
    const { plaintext } = await decryptEnvelope(key.jwk, { protected: protectedB64!, iv: iv!, tag: tag!, ciphertext })
    const text = new TextDecoder().decode(plaintext)
    let obj: unknown = null
    try {
      obj = JSON.parse(text)
    } catch {
      obj = null
    }
    emit(c, {
      event: 'message_decrypted', identity: await identityHash(id.iss, id.sub), kid: header.kid, size: ciphertext.byteLength, ms: Date.now() - started, fetched_by: 'agent',
    })
    const warnings: string[] = []
    return c.json(
      obj && typeof obj === 'object' && !Array.isArray(obj)
        ? { kid: header.kid, size: ciphertext.byteLength, plaintext: obj, warnings }
        : { kid: header.kid, size: ciphertext.byteLength, text, warnings },
    )
  } catch (err) {
    if (err instanceof JweError) {
      emit(c, { event: 'decrypt_refused', level: 40, code: err.code, kid: header.kid })
      return c.json({ error: err.code, detail: err.message }, 400)
    }
    throw err
  }
})

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const now = nowIso()
    const r = await env.DB.prepare('DELETE FROM private_keys WHERE purge_after IS NOT NULL AND purge_after < ?').bind(now).run()
    if (r.meta.changes) emitBackground(env, ctx, { event: 'key_purged', count: r.meta.changes })
  },
}

// decrypt.aauth.dev — the decrypt Worker (plan A4, A5, D26). Public:
// well-known (resource and agent), JWKS, OpenAPI, pages. Protected (person
// token): getKey, rotateKey, getKeys, decryptEnvelope, getMessage (the
// chained download, D1).
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { requireIdentity, parseJsonBody } from './auth'
import { getPublicJWK } from './crypto'
import { emit, emitBackground } from './events'
import { agentDocument } from './agent-identity'
import { currentKey, listKeys, mintKey, publicRecord } from './keys'
import { openapi } from './openapi'
import { answerDecrypted, getMessage } from './read'
import type { Env, HonoEnv } from './types'
import { B64URL_RE, b64urlDecode, identityHash, nowIso } from './util'

const app = new Hono<HonoEnv>()

app.onError((err, c) => {
  const error = err instanceof Error ? err : new Error(String(err))
  console.error('unhandled_error', error.stack ?? String(error))
  emit(c, { event: 'unhandled_error', level: 50, msg: error.message, error_name: error.name, error_stack: error.stack })
  return c.json({ error: 'internal_error' }, 500)
})

app.use('*', cors({ origin: '*', exposeHeaders: ['AAuth-Requirement', 'Signature-Error', 'Accept-Signature', 'Accept-Signature-Scheme', 'Accept-Signature-Alg'] }))

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
// D1, D24: decrypt is an intermediary toward the messaging service for the
// chained download (getMessage). A PS verifies the agent token against
// jwks_uri.
app.get('/.well-known/aauth-agent.json', (c) => c.json(agentDocument(c.env.ORIGIN)))
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
  if (!ciphertext) return c.json({ error: 'invalid_request', field: 'ciphertext', detail: 'empty' }, 400)
  return answerDecrypted(c, { protected: protectedB64!, iv: iv!, tag: tag!, ciphertext }, 'agent')
})

app.get('/messages/:id', requireIdentity, getMessage)

// The page paths listed in run_worker_first reach the Worker on every host;
// on the live host they are served from the assets binding here.
app.notFound((c) => (c.env.ASSETS ? c.env.ASSETS.fetch(c.req.raw) : c.text('not found', 404)))

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const now = nowIso()
    const r = await env.DB.prepare('DELETE FROM private_keys WHERE purge_after IS NOT NULL AND purge_after < ?').bind(now).run()
    if (r.meta.changes) emitBackground(env, ctx, { event: 'key_purged', count: r.meta.changes })
  },
}

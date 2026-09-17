// The read service Worker (plan A4, A5, D26; D27 section 7). Public:
// well-known (resource and agent), JWKS, OpenAPI, pages. Protected (person
// token): readMessage (the chained download and decrypt), getKey, rotateKey,
// getKeys. Host names come from env.
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { requireIdentity } from './auth'
import { getPublicJWK } from './crypto'
import { emit, emitBackground } from './events'
import { agentDocument } from './agent-identity'
import { currentKey, listKeys, mintKey, publicRecord } from './keys'
import { rotateKey } from './rotate'
import { openapi } from './openapi'
import { readMessage } from './read'
import type { Env, HonoEnv } from './types'
import { identityHash, nowIso } from './util'

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
    name: new URL(origin).host,
    description: 'A read service: holds the private keys that decrypt your end-to-end encrypted messages, and reads a message for your agent by downloading it from your messaging service and decrypting it. The code is open and you can run your own.',
    access_mode: 'person-token',
    r3_vocabularies: { 'urn:aauth:vocabulary:openapi': `${origin}/openapi.json` },
    contact: { feedback: 'feedback@agent.coop', abuse: 'abuse@agent.coop' },
    llms_txt: `${origin}/llms.txt`,
  })
})
// This service is an intermediary toward the messaging service (readMessage,
// rotateKey). A PS verifies the agent token against jwks_uri.
app.get('/.well-known/aauth-agent.json', (c) => c.json(agentDocument(c.env.ORIGIN)))
app.get('/.well-known/jwks.json', async (c) => c.json({ keys: [await getPublicJWK(c.env.SIGNING_KEY)] }))
app.get('/openapi.json', (c) => c.json(openapi(c.env)))
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

app.post('/key', requireIdentity, rotateKey)

app.get('/keys', requireIdentity, async (c) => {
  const id = c.get('identity')
  const rows = await listKeys(c.env, id.iss, id.sub)
  return c.json({ keys: rows.map(publicRecord) })
})

app.post('/read', requireIdentity, readMessage)

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

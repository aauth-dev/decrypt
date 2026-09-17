// rotateKey (D27, sections 5b and 5c). Mints a new key; older keys stay, so
// messages already stored under an old kid still decrypt here (5d).
//
//   5c  The agent called: chain to the messaging service's setPublicKey
//       {kid, alg, jwk} so it has the new key, and return the key with its
//       answer. `resource` is optional, default DEFAULT_RESOURCE. If
//       setPublicKey fails the new key is removed again, so both ends stay
//       in step.
//   5b  The messaging service called (its rotatePublicKey): the person
//       token's agent_id is on the host of `resource`. It stores what this
//       returns, so there is no call back. That is the whole of "no loop"
//       on this side: setPublicKey is called only when the rotate request
//       did not come from the messaging service.
import type { Context } from 'hono'
import { agentHost, parseJsonBody } from './auth'
import { chainedFetch, passThrough } from './chain'
import { emit } from './events'
import { mintKey, publicRecord } from './keys'
import { resourceOf } from './read'
import type { HonoEnv } from './types'
import { identityHash } from './util'

export async function rotateKey(c: Context<HonoEnv>): Promise<Response> {
  const id = c.get('identity')
  const who = await identityHash(id.iss, id.sub)
  const body = parseJsonBody<{ resource?: unknown }>(c)
  if (!body) return c.json({ error: 'invalid_json' }, 400)
  const resource = resourceOf(c.env.DEFAULT_RESOURCE, body.resource)
  if (!resource) return c.json({ error: 'invalid_request', field: 'resource', detail: 'your messaging service, as an https origin; leave it out for the default' }, 400)

  const row = await mintKey(c.env, id.iss, id.sub)
  const key = publicRecord(row)
  const fromMessagingService = agentHost(id.agent_id) === new URL(resource).host
  emit(c, { event: 'key_rotated', identity: who, kid: row.kid, caller: fromMessagingService ? 'messaging_service' : 'agent', agent_id: id.agent_id, resource })
  if (fromMessagingService) return c.json(key)

  // ── 5c: tell the messaging service ──
  const unmint = () => c.env.DB.prepare('DELETE FROM private_keys WHERE ps_iss = ? AND ps_sub = ? AND kid = ?').bind(id.iss, id.sub, row.kid).run()
  const chain = await chainedFetch(c.env, id.jwt, resource)
  if (!chain.ok) {
    await unmint()
    emit(c, { event: 'chain_failed', level: 40, step: 'person_token', code: chain.error, detail: chain.detail, ps: id.iss, resource, identity: who })
    return c.json({ error: chain.error, detail: `no person token for ${resource} from ${id.iss}: ${chain.detail}; your key is unchanged`, step: 'person_token', resource }, 502)
  }
  let res: Response
  try {
    res = await chain.fetch(`${resource}/public-key`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ kid: key.kid, alg: key.alg, jwk: key.jwk }),
    })
  } catch (err) {
    await unmint()
    emit(c, { event: 'chain_failed', level: 40, step: 'set_public_key', code: 'resource_unreachable', detail: String(err), resource, identity: who })
    return c.json({ error: 'resource_unreachable', detail: `${resource} did not answer: ${String(err)}; your key is unchanged`, step: 'set_public_key', resource }, 502)
  }
  if (res.status !== 200) {
    await unmint()
    const refusal = await passThrough(res)
    emit(c, { event: 'set_public_key_refused', level: 40, code: refusal.error, status: res.status, resource, identity: who })
    return c.json({ ...refusal, step: 'set_public_key', resource }, (res.status === 401 ? 502 : res.status) as 403)
  }
  const answer = (await res.json().catch(() => ({}))) as Record<string, unknown>
  emit(c, { event: 'public_key_set', identity: who, kid: row.kid, resource })
  return c.json({ ...key, resource, set_public_key: answer })
}

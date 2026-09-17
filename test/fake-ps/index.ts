// A fake Person Server for the test build, copied from
// secret-agent-coop/service/test/fake-ps (a shared package is increment 7).
// Runs inside the Workers test isolate: issues person tokens with a sub
// directed per audience, exchanges resource tokens for auth tokens, and
// serves an HTTP person_token_endpoint for call chaining: it verifies the
// intermediary's signed request and agent token (against the issuer's
// aauth-agent.json → jwks_uri, through SELF), verifies the upstream_token,
// and issues a person token for the requested resource with no
// interaction. Its documents are served through a mocked global fetch.
//
// Also here: a fake messaging service at SECRET (deliberately not an
// agent.coop host: the Worker under test must take the target from the
// request or from DEFAULT_RESOURCE) with downloadMessage and setPublicKey,
// verifying the signature and the chained person token and recording what
// arrived.
//
// Also here: an Agent that plays the AAuth MCP against the Worker under
// test — signs requests with RFC 9421 (jwt scheme) and follows
// AAuth-Requirement challenges the way @aauth/proxy does.

import { SELF } from 'cloudflare:test'
import { calculateThumbprint, fetch as httpsigFetch, verify as httpsigVerify } from '@hellocoop/httpsig'
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose'
import { parseRequirementHeader } from '@aauth/protocol'

export const PS = 'https://ps.fake.test'
/** the Worker under test */
export const RESOURCE = 'https://decrypt.aauth.dev'
/** the fake messaging service in the outbound mock */
export const SECRET = 'https://secret.fake.test'

export interface TestKey {
  privateKey: CryptoKey
  privateJwk: JsonWebKey
  publicJwk: JsonWebKey & { kid: string }
}

export async function generateEd25519(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey & { d?: string; key_ops?: string[]; ext?: boolean }
  privateJwk.alg = 'Ed25519'
  const { d: _d, key_ops: _ko, ext: _ext, ...pub } = privateJwk
  const publicJwk = { ...pub, key_ops: ['verify'], alg: 'Ed25519' }
  const kid = await calculateThumbprint(publicJwk)
  return { privateKey: pair.privateKey, privateJwk, publicJwk: { ...publicJwk, kid } }
}

export const now = () => Math.floor(Date.now() / 1000)

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function cnfJwk(key: TestKey): JsonWebKey {
  const { kid: _kid, key_ops: _ko, ...jwk } = key.publicJwk
  return jwk
}

// ── Outbound fetch mock ──
// Tests and the worker under test share one isolate, so replacing
// globalThis.fetch serves the PS's discovery documents. SELF.fetch and
// bindings are unaffected.
type RouteHandler = (req: Request) => Response | Promise<Response>
const routes = new Map<string, RouteHandler>()
/** handlers keyed by a URL prefix, for paths with ids and queries */
const prefixRoutes = new Map<string, RouteHandler>()
let installed = false
export function installMockFetch(): void {
  if (installed) return
  installed = true
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init)
    const url = new URL(req.url)
    const handler = routes.get(req.url) ?? routes.get(url.origin + url.pathname) ?? [...prefixRoutes.entries()].find(([p]) => req.url.startsWith(p))?.[1]
    if (!handler) throw new Error(`unmocked outbound fetch: ${req.url}`)
    return handler(req)
  }) as typeof fetch
}

/** RFC 9421 verification of a mocked outbound request, jwt scheme. */
async function verifySigned(req: Request, opts: { requireContentDigest?: boolean } = {}) {
  const url = new URL(req.url)
  const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : new Uint8Array(await req.arrayBuffer())
  const sig = await httpsigVerify(
    { method: req.method, authority: url.host, path: url.pathname, query: url.search ? url.search.slice(1) : undefined, headers: req.headers, ...(body ? { body } : {}) },
    opts,
  )
  return { sig, body }
}

const problem = (status: number, error: string, detail: string) =>
  Response.json({ error, detail }, { status, headers: { 'content-type': 'application/problem+json' } })

// ── The fake PS ──

export interface Person {
  /** stable handle inside the fake PS; subs are derived per audience */
  handle: string
  email: string
  name?: string
}

export class FakePS {
  private key!: TestKey
  private issued = new Set<string>()
  /** every directed sub this PS has minted, back to the person (Hellō has its own record) */
  private subs = new Map<string, Person>()
  /** POSTs to the HTTP person_token_endpoint (the chain), for idempotency tests */
  personTokenRequests = 0
  /** the last agent token an intermediary presented at the person_token_endpoint */
  lastAgentToken?: string
  /** when set, the upstream token's aud must equal this instead of the agent token's iss (to force invalid_upstream_token) */
  expectedIntermediary?: string

  /** A second instance with another iss plays an issuer secret does not trust for email. */
  constructor(readonly iss: string = PS) {}

  async init(): Promise<this> {
    this.key = await generateEd25519()
    installMockFetch()
    routes.set(`${this.iss}/aauth/token/person`, (req) => this.personTokenEndpoint(req))
    routes.set(`${this.iss}/.well-known/aauth-person.json`, () =>
      Response.json({
        issuer: this.iss,
        jwks_uri: `${this.iss}/jwks.json`,
        person_token_endpoint: `${this.iss}/aauth/token/person`,
        auth_token_endpoint: `${this.iss}/aauth/token/auth`,
        scopes_supported: ['email', 'profile'],
        claims_supported: ['sub', 'email', 'name'],
      }),
    )
    routes.set(`${this.iss}/jwks.json`, () => Response.json({ keys: [this.key.publicJwk] }))
    return this
  }

  /** Pairwise pseudonymous sub per audience (protocol §Directed Identifiers). */
  async sub(person: Person, aud: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${person.handle}|${aud}`))
    const sub = b64url(new Uint8Array(digest))
    this.subs.set(sub, person)
    return sub
  }

  private async publicKey() {
    const { alg: _a, kid: _k, key_ops: _o, ...jwk } = this.key.publicJwk as JsonWebKey & { alg?: string; kid?: string; key_ops?: string[] }
    return importJWK(jwk as never, 'Ed25519')
  }

  /**
   * POST /aauth/token/person over HTTP (D26, call chaining only; agents in
   * these tests get their person tokens in-process). Mirrors what Hellō
   * checks (Wallet svr/src/aauth/verify-upstream-token.js): the signed
   * request, the agent token against the issuer's aauth-agent.json →
   * jwks_uri, then the upstream token: issued by this PS, person or auth
   * typ, aud equal to the agent token's iss, not expired. The person is the
   * one behind the upstream sub. Issues a person token for body.resource
   * with cnf = the agent token's key. No interaction.
   */
  private async personTokenEndpoint(req: Request): Promise<Response> {
    this.personTokenRequests++
    if (req.method !== 'POST') return problem(405, 'method_not_allowed', 'POST only')
    const { sig, body } = await verifySigned(req, { requireContentDigest: true })
    if (!sig.verified) return problem(401, 'signature_verification_failed', sig.error ?? 'bad signature')
    if (sig.keyType !== 'jwt' || !sig.jwt) return problem(401, 'invalid_agent_token', 'Signature-Key must be sig=jwt')
    const agentJwt = sig.jwt.raw
    const header = decodeProtectedHeader(agentJwt)
    if (header.typ !== 'aa-agent+jwt' || header.alg !== 'Ed25519' || typeof header.kid !== 'string') return problem(401, 'invalid_agent_token', `header typ=${String(header.typ)} alg=${String(header.alg)} kid=${String(header.kid)}`)
    const agent = decodeJwt(agentJwt) as Record<string, unknown>
    if (typeof agent.iss !== 'string' || agent.dwk !== 'aauth-agent.json' || typeof agent.sub !== 'string' || !/^aauth:[A-Za-z0-9\-_+.]+@[^@\s]+$/.test(agent.sub)) {
      return problem(401, 'invalid_agent_token', 'iss, dwk aauth-agent.json, and sub aauth:local@domain are required')
    }
    // Hellō requires jti on an agent token since Wallet 2026.9.24 (#4302): 401 without one.
    if (typeof agent.jti !== 'string' || !agent.jti) return problem(401, 'invalid_agent_token', 'jti required')
    const cnf = (agent.cnf as { jwk?: JsonWebKey } | undefined)?.jwk
    if (!cnf) return problem(401, 'invalid_agent_token', 'cnf.jwk required')
    // The issuer's agent document and JWKS, through SELF: the issuer is the Worker under test.
    const doc = await SELF.fetch(`${agent.iss}/.well-known/aauth-agent.json`)
    if (doc.status !== 200) return problem(401, 'invalid_agent_token', `no aauth-agent.json at ${agent.iss}`)
    const { jwks_uri } = (await doc.json()) as { jwks_uri: string }
    const jwks = (await (await SELF.fetch(jwks_uri)).json()) as { keys: Array<JsonWebKey & { kid?: string; alg?: string }> }
    const key = jwks.keys.find((k) => k.kid === header.kid)
    if (!key) return problem(401, 'invalid_agent_token', `kid ${header.kid} not at ${jwks_uri}`)
    const { alg: _a, kid: _k, key_ops: _o, ...importable } = key
    try {
      await jwtVerify(agentJwt, await importJWK(importable as never, 'Ed25519'), { issuer: agent.iss })
    } catch (err) {
      return problem(401, 'invalid_agent_token', `signature: ${String(err)}`)
    }
    this.lastAgentToken = agentJwt

    const text = new TextDecoder().decode(body ?? new Uint8Array())
    let params: Record<string, unknown>
    try {
      params = JSON.parse(text) as Record<string, unknown>
    } catch {
      return problem(400, 'invalid_request', 'JSON body required')
    }
    if (typeof params.resource !== 'string') return problem(400, 'invalid_request', 'resource required')
    if (typeof params.upstream_token !== 'string') return problem(400, 'invalid_request', 'this fake only serves chained requests (upstream_token)')
    if (params.mission_s256) return problem(400, 'invalid_request', 'mission_s256 must not accompany upstream_token')

    // The upstream token.
    let upstream: Record<string, unknown>
    try {
      upstream = (await jwtVerify(params.upstream_token, await this.publicKey(), { issuer: this.iss })).payload as Record<string, unknown>
    } catch (err) {
      return problem(400, 'invalid_upstream_token', `not issued by this PS or expired: ${String(err)}`)
    }
    const upstreamTyp = decodeProtectedHeader(params.upstream_token).typ
    if (upstreamTyp !== 'aa-person+jwt' && upstreamTyp !== 'aa-auth+jwt') return problem(400, 'invalid_upstream_token', `typ ${String(upstreamTyp)}`)
    const mustEqual = this.expectedIntermediary ?? agent.iss
    if (upstream.aud !== mustEqual) return problem(400, 'invalid_upstream_token', `aud ${String(upstream.aud)} is not the intermediary ${mustEqual}`)
    const person = typeof upstream.sub === 'string' ? this.subs.get(upstream.sub) : undefined
    if (!person) return problem(400, 'invalid_upstream_token', 'unknown sub')

    // Hellō puts the agent the token is issued to on person tokens for the
    // messaging service (Wallet passthrough-claims.js): here, the intermediary.
    const personToken = await this.sign('aa-person+jwt', {
      iss: this.iss, dwk: 'aauth-person.json', aud: params.resource, sub: await this.sub(person, params.resource), cnf: { jwk: cnf }, agent_id: agent.sub,
    }, 600)
    return Response.json({ person_token: personToken, expires_in: 600 })
  }

  /** Verify a person token this PS issued, for the fake decrypt. */
  async verifyPersonToken(jwt: string, aud: string): Promise<Record<string, unknown>> {
    if (decodeProtectedHeader(jwt).typ !== 'aa-person+jwt') throw new Error('not a person token')
    return (await jwtVerify(jwt, await this.publicKey(), { issuer: this.iss, audience: aud })).payload as Record<string, unknown>
  }

  private async sign(typ: string, claims: Record<string, unknown>, lifetime: number): Promise<string> {
    const t = now()
    const jti = b64url(crypto.getRandomValues(new Uint8Array(16)))
    this.issued.add(jti)
    return new SignJWT({ iat: t, exp: t + lifetime, jti, ...claims })
      .setProtectedHeader({ alg: 'Ed25519', typ, kid: this.key.publicJwk.kid } as never)
      .sign(this.key.privateKey)
  }

  async personToken(person: Person, agent: TestKey, aud = RESOURCE, overrides: Record<string, unknown> = {}): Promise<string> {
    return this.sign('aa-person+jwt', {
      iss: this.iss, dwk: 'aauth-person.json', aud, sub: await this.sub(person, aud), cnf: { jwk: cnfJwk(agent) }, ...overrides,
    }, 600)
  }

  /**
   * POST /aauth/token/auth, in-process. Verifies the resource token against
   * the resource's JWKS (fetched through SELF), checks presented_jti, then
   * issues an auth token for the requested scope. Auto-approves.
   */
  async exchange(person: Person, agent: TestKey, resourceToken: string, presentedToken: string): Promise<string> {
    const header = decodeProtectedHeader(resourceToken)
    if (header.typ !== 'aa-resource+jwt') throw new Error(`fake PS: resource token typ ${header.typ}`)
    const rt = decodeJwt(resourceToken) as Record<string, unknown>
    if (rt.aud !== this.iss) throw new Error(`fake PS: resource token aud ${String(rt.aud)} is not me`)
    if (rt.ps !== this.iss) throw new Error('fake PS: resource token ps is not me')
    const jwksRes = await SELF.fetch(`${String(rt.iss)}/.well-known/jwks.json`)
    const jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
    const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === header.kid) ?? jwks.keys[0]
    const { alg: _a, ...importable } = jwk as JsonWebKey & { alg?: string }
    await jwtVerify(resourceToken, await importJWK(importable as never, 'Ed25519'), { audience: this.iss })
    const presented = decodeJwt(presentedToken) as Record<string, unknown>
    if (presented.jti !== rt.presented_jti) throw new Error('fake PS: presented_jti mismatch')
    if (presented.sub !== rt.sub) throw new Error('fake PS: sub mismatch')
    const agentJkt = await calculateThumbprint(cnfJwk(agent))
    if (rt.agent_jkt !== agentJkt) throw new Error('fake PS: agent_jkt mismatch')

    const scope = String(rt.scope ?? '')
    const claims: Record<string, unknown> = {
      iss: this.iss, dwk: 'aauth-person.json', aud: rt.iss, ps: this.iss, sub: rt.sub, cnf: { jwk: cnfJwk(agent) }, scope,
    }
    if (scope.split(/\s+/).includes('email')) {
      // login_hint selects an address the person holds; otherwise the person
      // "picks" their default. A hint for an address they do not hold is
      // ignored, as Hellō would prompt to verify it and we cannot.
      const hint = typeof rt.login_hint === 'string' ? rt.login_hint.toLowerCase() : undefined
      const held = [person.email, ...(person.altEmails ?? [])].map((e) => e.toLowerCase())
      claims.email = hint && held.includes(hint) ? hint : person.email
      claims.email_verified = true
    }
    if (scope.split(/\s+/).includes('profile') && person.name) claims.name = person.name
    return this.sign('aa-auth+jwt', claims, 3600)
  }
}

export interface Person {
  altEmails?: string[]
}

// ── The fake messaging service ──
// What this service chains to. Verifies the signature and the chained
// person token (issued by the fake PS, aud SECRET, cnf = the signing key),
// then behaves like secret.agent.coop's downloadMessage and setPublicKey
// (plan read-send-services sections 4c, 5c): `inbox` messages waiting per
// recipient sub, `publicKeys` the latest key per sub, `readServiceHost` the
// host setPublicKey accepts.

export interface InboxMessage {
  id: string
  /** the recipient's sub at SECRET */
  sub: string
  from: string
  from_name?: string
  to: string
  jwe?: string
  system?: Record<string, unknown>
  state: 'new' | 'downloaded'
}

export class FakeSecret {
  readonly origin = SECRET
  /** "METHOD path" of every authenticated request, in order */
  requests: string[] = []
  /** subs and agent_ids seen on chained person tokens */
  seen: string[] = []
  agentIds: unknown[] = []
  /** messages waiting for download, by id */
  inbox = new Map<string, InboxMessage>()
  /** Accept header of each GET /messages/{id} */
  downloadAccepts: string[] = []
  /** the latest public key per sub, as setPublicKey stored it */
  publicKeys = new Map<string, { kid: string; alg: string; jwk: JsonWebKey }>()
  /** every setPublicKey body that arrived, accepted or not */
  setPublicKeyCalls: Array<Record<string, unknown>> = []
  /** setPublicKey accepts only an agent_id on this host: the person's read service */
  readServiceHost = new URL(RESOURCE).host
  /** the next setPublicKey answers with this */
  failNextSetPublicKey?: { status: number; error: string; detail?: string }

  constructor(readonly ps: FakePS) {
    installMockFetch()
    routes.set(`${SECRET}/public-key`, (req) => this.setPublicKey(req))
    prefixRoutes.set(`${SECRET}/messages/`, (req) => this.downloadMessage(req))
  }

  private async auth(req: Request): Promise<{ sub: string; agent_id: unknown; body?: Uint8Array } | Response> {
    const { sig, body } = await verifySigned(req)
    if (!sig.verified) return problem(401, 'signature_verification_failed', sig.error ?? 'bad signature')
    if (sig.keyType !== 'jwt' || !sig.jwt) return problem(401, 'person_token_required', 'sig=jwt required')
    let claims: Record<string, unknown>
    try {
      claims = await this.ps.verifyPersonToken(sig.jwt.raw, SECRET)
    } catch (err) {
      return problem(401, 'invalid_token', String(err))
    }
    const cnf = (claims.cnf as { jwk?: JsonWebKey } | undefined)?.jwk
    if (!cnf || (await calculateThumbprint(cnf)) !== sig.thumbprint) return problem(401, 'cnf_mismatch', 'the request is not signed with the token\'s key')
    const url = new URL(req.url)
    this.requests.push(`${req.method} ${url.pathname}`)
    this.seen.push(String(claims.sub))
    this.agentIds.push(claims.agent_id)
    return { sub: String(claims.sub), agent_id: claims.agent_id, body }
  }

  /** secret's downloadMessage: JSON with the compact JWE; 406 use_read_service without Accept: application/json. */
  private async downloadMessage(req: Request): Promise<Response> {
    const a = await this.auth(req)
    if (a instanceof Response) return a
    const id = decodeURIComponent(new URL(req.url).pathname.slice('/messages/'.length))
    const m = this.inbox.get(id)
    if (!m || m.sub !== a.sub) return Response.json({ error: 'not_found' }, { status: 404 })
    const accept = req.headers.get('accept') ?? ''
    this.downloadAccepts.push(accept)
    const base = { id: m.id, from: m.from, ...(m.from_name ? { from_name: m.from_name } : {}), to: m.to }
    if (m.system) {
      m.state = 'downloaded'
      return Response.json({ ...base, created_at: '2026-09-17T00:00:00.000Z', system: m.system })
    }
    if (!accept.includes('application/json')) return Response.json({ error: 'use_read_service', read_message_with: { resource: RESOURCE, op_id: 'readMessage' } }, { status: 406 })
    m.state = 'downloaded'
    let kid: unknown
    try {
      kid = (JSON.parse(new TextDecoder().decode(b64urlDecode(m.jwe!.split('.')[0]))) as { kid?: unknown }).kid
    } catch {
      kid = undefined
    }
    return Response.json({ ...base, kid, size: m.jwe!.length, created_at: '2026-09-17T00:00:00.000Z', jwe: m.jwe })
  }

  /** secret's setPublicKey: only from the person's read service. */
  private async setPublicKey(req: Request): Promise<Response> {
    const a = await this.auth(req)
    if (a instanceof Response) return a
    if (req.method !== 'PUT') return problem(405, 'method_not_allowed', 'PUT only')
    const body = JSON.parse(new TextDecoder().decode(a.body)) as Record<string, unknown>
    this.setPublicKeyCalls.push(body)
    if (this.failNextSetPublicKey) {
      const f = this.failNextSetPublicKey
      this.failNextSetPublicKey = undefined
      return Response.json({ error: f.error, detail: f.detail ?? f.error }, { status: f.status })
    }
    const host = typeof a.agent_id === 'string' ? a.agent_id.slice(a.agent_id.lastIndexOf('@') + 1) : null
    if (host !== this.readServiceHost) return Response.json({ error: 'not_read_service', detail: 'agent_id is not the person\'s read service' }, { status: 403 })
    if (typeof body.kid !== 'string' || body.alg !== 'ECDH-ES' || !body.jwk) return Response.json({ error: 'invalid_key' }, { status: 400 })
    this.publicKeys.set(a.sub, { kid: body.kid, alg: 'ECDH-ES', jwk: body.jwk as JsonWebKey })
    return Response.json({ kid: body.kid, created_at: new Date().toISOString() })
  }
}

function b64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const bin = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// ── The agent (plays the AAuth MCP) ──

export interface CallOptions {
  body?: unknown // object → JSON; string / Uint8Array sent as-is
  contentType?: string
  accept?: string
  headers?: Record<string, string>
  /** start with an auth token instead of a person token (default person) */
  cred?: { kind: 'person' } | { kind: 'auth'; jwt: string }
}

export class Agent {
  key!: TestKey
  lastAuthToken?: string

  /**
   * `agentId` is what the Person Server says about the agent on the person
   * token (agent_id): the AAuth MCP by default; the messaging service's own
   * agent id when it chains here for rotatePublicKey (5b); null for a PS
   * that says nothing.
   */
  constructor(readonly ps: FakePS, readonly person: Person, readonly resource = RESOURCE, readonly agentId: string | null = 'aauth:agent@mcp.fake.test') {}

  private personToken(): Promise<string> {
    return this.ps.personToken(this.person, this.key, this.resource, this.agentId ? { agent_id: this.agentId } : {})
  }

  async init(): Promise<this> {
    this.key = await generateEd25519()
    return this
  }

  async signed(jwt: string, method: string, url: string, opts: CallOptions): Promise<Response> {
    let body: string | Uint8Array | undefined
    const headers: Record<string, string> = { ...(opts.headers ?? {}) }
    if (opts.body !== undefined) {
      if (typeof opts.body === 'string' || opts.body instanceof Uint8Array) {
        body = opts.body
        headers['content-type'] = opts.contentType ?? (typeof opts.body === 'string' ? 'text/plain' : 'application/octet-stream')
      } else {
        body = JSON.stringify(opts.body)
        headers['content-type'] = opts.contentType ?? 'application/json'
      }
    }
    if (opts.accept) headers.accept = opts.accept
    const { headers: signedHeaders } = await httpsigFetch(url, {
      dryRun: true,
      method,
      headers,
      ...(body !== undefined ? { body } : {}),
      signingKey: this.key.privateJwk,
      signatureKey: { type: 'jwt', jwt },
    })
    return SELF.fetch(url, { method, headers: signedHeaders as HeadersInit, ...(body !== undefined ? { body: body as BodyInit } : {}) })
  }

  /** One call with the requirement loop: person token → (auth-token challenge → exchange → retry). */
  async call(method: string, path: string, opts: CallOptions = {}): Promise<Response> {
    const url = `${this.resource}${path}`
    let jwt = opts.cred?.kind === 'auth' ? opts.cred.jwt : await this.personToken()
    for (let round = 0; round < 3; round++) {
      const res = await this.signed(jwt, method, url, opts)
      const header = res.headers.get('aauth-requirement')
      if (!header) return res
      const req = parseRequirementHeader(header)
      if (!req) return res
      if (req.requirement === 'auth-token' && req.resourceToken) {
        const authToken = await this.ps.exchange(this.person, this.key, req.resourceToken, jwt)
        this.lastAuthToken = authToken
        jwt = authToken
        continue
      }
      if (req.requirement === 'person-token') {
        jwt = await this.personToken()
        continue
      }
      return res
    }
    throw new Error('requirement loop exceeded')
  }

  async json<T = Record<string, unknown>>(method: string, path: string, opts: CallOptions = {}): Promise<{ status: number; body: T; res: Response }> {
    const res = await this.call(method, path, opts)
    const text = await res.text()
    let body: T
    try {
      body = JSON.parse(text) as T
    } catch {
      body = text as unknown as T
    }
    return { status: res.status, body, res }
  }
}

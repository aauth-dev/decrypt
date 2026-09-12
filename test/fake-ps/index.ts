// A fake Person Server for the test build (plan S4/S5). Runs inside the
// Workers test isolate: issues person tokens with a sub directed per
// audience, exchanges resource tokens for auth tokens (verifying the
// resource token's signature against the resource's JWKS), honours
// login_hint when the scope includes `email`, and auto-approves. Its
// well-known document and JWKS are served through a mocked global fetch,
// since @aauth/resource discovers `{iss}/.well-known/{dwk}` on the global.
//
// Also here: an Agent that plays the AAuth MCP against the Worker under
// test — signs requests with RFC 9421 (jwt scheme) and follows
// AAuth-Requirement challenges the way @aauth/proxy does.

import { SELF } from 'cloudflare:test'
import { calculateThumbprint, fetch as httpsigFetch } from '@hellocoop/httpsig'
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose'
import { parseRequirementHeader } from '@aauth/protocol'

export const PS = 'https://ps.fake.test'
export const RESOURCE = 'https://decrypt.agent.coop'

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
const routes = new Map<string, () => Response>()
let installed = false
export function installMockFetch(): void {
  if (installed) return
  installed = true
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const handler = routes.get(href)
    if (!handler) throw new Error(`unmocked outbound fetch: ${href}`)
    return handler()
  }) as typeof fetch
}

// ── The fake PS ──

export interface Person {
  /** stable handle inside the fake PS; subs are derived per audience */
  handle: string
  email: string
  name?: string
}

export class FakePS {
  readonly iss = PS
  private key!: TestKey
  private issued = new Set<string>()

  async init(): Promise<this> {
    this.key = await generateEd25519()
    installMockFetch()
    routes.set(`${PS}/.well-known/aauth-person.json`, () =>
      Response.json({
        issuer: PS,
        jwks_uri: `${PS}/jwks.json`,
        person_token_endpoint: `${PS}/aauth/token/person`,
        auth_token_endpoint: `${PS}/aauth/token/auth`,
        scopes_supported: ['email', 'profile'],
        claims_supported: ['sub', 'email', 'name'],
      }),
    )
    routes.set(`${PS}/jwks.json`, () => Response.json({ keys: [this.key.publicJwk] }))
    return this
  }

  /** Pairwise pseudonymous sub per audience (protocol §Directed Identifiers). */
  async sub(person: Person, aud: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${person.handle}|${aud}`))
    return b64url(new Uint8Array(digest))
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
      iss: PS, dwk: 'aauth-person.json', aud, sub: await this.sub(person, aud), cnf: { jwk: cnfJwk(agent) }, ...overrides,
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
    if (rt.aud !== PS) throw new Error(`fake PS: resource token aud ${String(rt.aud)} is not me`)
    if (rt.ps !== PS) throw new Error('fake PS: resource token ps is not me')
    const jwksRes = await SELF.fetch(`${String(rt.iss)}/.well-known/jwks.json`)
    const jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
    const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === header.kid) ?? jwks.keys[0]
    const { alg: _a, ...importable } = jwk as JsonWebKey & { alg?: string }
    await jwtVerify(resourceToken, await importJWK(importable as never, 'Ed25519'), { audience: PS })
    const presented = decodeJwt(presentedToken) as Record<string, unknown>
    if (presented.jti !== rt.presented_jti) throw new Error('fake PS: presented_jti mismatch')
    if (presented.sub !== rt.sub) throw new Error('fake PS: sub mismatch')
    const agentJkt = await calculateThumbprint(cnfJwk(agent))
    if (rt.agent_jkt !== agentJkt) throw new Error('fake PS: agent_jkt mismatch')

    const scope = String(rt.scope ?? '')
    const claims: Record<string, unknown> = {
      iss: PS, dwk: 'aauth-person.json', aud: rt.iss, ps: PS, sub: rt.sub, cnf: { jwk: cnfJwk(agent) }, scope,
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

  constructor(readonly ps: FakePS, readonly person: Person, readonly resource = RESOURCE) {}

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
    let jwt = opts.cred?.kind === 'auth' ? opts.cred.jwt : await this.ps.personToken(this.person, this.key, this.resource)
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
        jwt = await this.ps.personToken(this.person, this.key, this.resource)
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

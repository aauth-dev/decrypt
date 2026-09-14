export interface Env {
  SERVICE: string
  ORIGIN: string
  /** hosts still routed here but retired: pages redirect, API 404 */
  LEGACY_HOSTS?: string
  KEK: string // 32 bytes base64url, secret
  SIGNING_KEY: string // Ed25519 private JWK (JSON), secret
  DB: D1Database
  ASSETS?: Fetcher
  EVENTS_QUEUE?: Queue
}

export interface Identity {
  iss: string
  sub: string
  kind: 'person' | 'auth'
  thumbprint: string
}

export type HonoEnv = { Bindings: Env; Variables: { identity: Identity; rawBody: Uint8Array | undefined } }

export interface KeyRow {
  ps_iss: string
  ps_sub: string
  kid: string
  alg: string
  private_jwk: string
  public_jwk: string
  created_at: string
  retired_at: string | null
  purge_after: string | null
}

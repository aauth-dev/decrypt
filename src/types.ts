export interface Env {
  SERVICE: string
  ORIGIN: string
  KEK: string // 32 bytes base64url, secret
  SIGNING_KEY: string // Ed25519 private JWK (JSON), secret: signs the agent token
  AGENT_KEY: string // Ed25519 private JWK (JSON), secret: signs requests made as an intermediary (getMessage)
  DB: D1Database
  ASSETS?: Fetcher
  EVENTS_QUEUE?: Queue
}

export interface Identity {
  iss: string
  sub: string
  kind: 'person' | 'auth'
  /** the presented token, verbatim: the upstream_token when getMessage chains */
  jwt: string
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

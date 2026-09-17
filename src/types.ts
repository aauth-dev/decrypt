export interface Env {
  SERVICE: string
  ORIGIN: string
  DEFAULT_RESOURCE: string // the messaging service readMessage and rotateKey talk to when the caller names none (Q7)
  KEK: string // 32 bytes base64url, secret
  SIGNING_KEY: string // Ed25519 private JWK (JSON), secret: signs the agent token
  AGENT_KEY: string // Ed25519 private JWK (JSON), secret: signs requests made as an intermediary (readMessage, rotateKey)
  DB: D1Database
  ASSETS?: Fetcher
  EVENTS_QUEUE?: Queue
}

export interface Identity {
  iss: string
  sub: string
  kind: 'person' | 'auth'
  /** the presented token, verbatim: the upstream_token when readMessage or rotateKey chains */
  jwt: string
  thumbprint: string
  /** the agent the token was issued to (aauth:local@domain), when the Person Server says: rotateKey uses it to see the messaging service calling (5b) */
  agent_id?: string
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

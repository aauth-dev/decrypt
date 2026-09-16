-- decrypt schema (plan A6). One row per private key, keyed by
-- the person's directed identity at this service and the key id.
CREATE TABLE private_keys (
  ps_iss       TEXT NOT NULL,
  ps_sub       TEXT NOT NULL,
  kid          TEXT NOT NULL,
  alg          TEXT NOT NULL,                -- ECDH-ES
  private_jwk  TEXT NOT NULL,                -- wrapped: base64url(iv).base64url(AES-256-GCM(KEK, jwk JSON, aad = iss|sub|kid))
  public_jwk   TEXT NOT NULL,                -- JSON
  created_at   TEXT NOT NULL,
  retired_at   TEXT,
  purge_after  TEXT,
  PRIMARY KEY (ps_iss, ps_sub, kid)
);
CREATE INDEX private_keys_purge ON private_keys(purge_after);

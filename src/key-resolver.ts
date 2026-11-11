// Key discovery. Every key this service looks up goes through one
// @hellocoop/httpsig key resolver on one store: the person server's (or
// access server's) key for the token presented to requireIdentity
// (auth.ts, through verifyToken), and the key of a server that signs a
// revocation as itself with the jwks_uri scheme (revocation.ts, through
// verify). The resolver holds the policy of draft-hardt-httpbis-signature-key
// §Caching and Performance: a fetch timeout, a one-minute refetch floor that
// also holds after a failed fetch, one refresh on an unknown kid,
// Cache-Control max-age honored down to the floor. The store is per isolate
// and bounded: its keys are URLs taken from requests that have not been
// verified yet.
import type { Context } from 'hono'
import { BoundedTtlCache, createKeyResolver, type KeyFetchEvent, type KeyResolver, type KeyStoreEntry } from '@hellocoop/httpsig'
import { emit } from './events'
import type { HonoEnv } from './types'

/** The freshness cap: the 10 minutes @aauth/resource's verifyToken used before. */
const MAX_TTL_MS = 600_000

const keyStore = new BoundedTtlCache<KeyStoreEntry>(500)

/** Tests only: forget every cached document, and with them the refetch floor. */
export function clearKeyCache(): void {
  keyStore.clear()
}

/**
 * The key resolver for one request. Every metadata and JWKS fetch it makes
 * is emitted as `aauth.decrypt.key_fetch`, with the request it was made for
 * and the reason for the fetch. Resolvers share the store, so the cache and
 * the refetch floor hold across requests.
 */
export function keyResolverFor(c: Context<HonoEnv>): KeyResolver {
  return createKeyResolver({
    store: keyStore,
    maxTtlMs: MAX_TTL_MS,
    onFetch: (event: KeyFetchEvent) =>
      emit(c, {
        event: 'aauth.decrypt.key_fetch',
        level: event.ok ? 30 : 40,
        msg: `${event.doc} fetch ${event.ok ? 'ok' : 'failed'} (${event.reason}): ${event.url}`,
        ...event,
      }),
  })
}

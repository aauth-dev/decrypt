import type { Env } from '../src/types'
import type { D1Migration } from 'cloudflare:test'

declare module 'cloudflare:test' {
  interface ProvidedEnv extends Env {
    TEST_MIGRATIONS: D1Migration[]
  }
}

import { defineConfig } from 'vitest/config'
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin'

const TEST_SIGNING_KEY = JSON.stringify({
  kty: 'OKP', crv: 'Ed25519',
  d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
  alg: 'Ed25519',
})
// Deterministic test KEK (32 zero-ish bytes); the deployed KEK is a secret.
export const TEST_KEK = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'

export default defineConfig(async () => {
  const migrations = await readD1Migrations('migrations')
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: { bindings: { SIGNING_KEY: TEST_SIGNING_KEY, KEK: TEST_KEK, TEST_MIGRATIONS: migrations } },
      }),
    ],
    test: { include: ['test/**/*.test.ts'], setupFiles: ['./test/apply-migrations.ts'] },
  }
})

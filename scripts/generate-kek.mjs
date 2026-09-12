// 32 random bytes, base64url, for `wrangler secret put KEK`.
import { randomBytes } from 'node:crypto'
console.log(randomBytes(32).toString('base64url'))

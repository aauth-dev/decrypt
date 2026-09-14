// OpenAPI 3.1 for decrypt.aauth.dev, served at /openapi.json.
export function openapi(origin: string) {
  const key = { $ref: '#/components/schemas/Key' }
  return {
    openapi: '3.1.0',
    info: {
      title: 'decrypt.aauth.dev',
      version: '0.1.0',
      description:
        'Holds the private key that decrypts your end-to-end encrypted messages and decrypts them for your agent; the default decrypt service for secret.agent.coop. Keys are P-256 for JWE ECDH-ES with A256GCM. Identity is your Person Server (iss, sub), directed to this service; it never sees an address.',
    },
    servers: [{ url: origin }],
    paths: {
      '/key': {
        get: {
          operationId: 'getKey',
          summary: 'Your current public key, created if you have none. secret.agent.coop createAccount registers it for you over a call chain; the manual path is addKey {kid, alg, jwk} there.',
          responses: { '200': { description: 'The key', content: { 'application/json': { schema: key } } } },
        },
        post: {
          operationId: 'rotateKey',
          summary: 'Mint a new key. Older keys stay decryptable. Register the new one at your messaging service (secret.agent.coop addKey).',
          responses: { '200': { description: 'The new key', content: { 'application/json': { schema: key } } } },
        },
      },
      '/keys': {
        get: {
          operationId: 'getKeys',
          summary: 'All your keys with state.',
          responses: { '200': { description: 'Keys', content: { 'application/json': { schema: { type: 'object', properties: { keys: { type: 'array', items: key } } } } } } },
        },
      },
      '/decrypt': {
        post: {
          operationId: 'decryptEnvelope',
          summary:
            'Decrypt one message. JSON body {protected, iv, tag, ciphertext} where ciphertext is base64url of the raw bytes from your messaging service (secret.agent.coop getMessage in its JSON form returns exactly these fields). Or application/octet-stream raw ciphertext with ?protected=&iv=&tag=. Returns {kid, size, plaintext, warnings}.',
          requestBody: { required: true, content: {
            'application/json': { schema: { type: 'object', required: ['protected', 'iv', 'tag', 'ciphertext'], properties: {
              protected: { type: 'string' }, iv: { type: 'string' }, tag: { type: 'string' }, ciphertext: { type: 'string', description: 'base64url' },
            } } },
            'application/octet-stream': { schema: { type: 'string', format: 'binary' } },
          } },
          parameters: [
            { name: 'protected', in: 'query', required: false, schema: { type: 'string' } },
            { name: 'iv', in: 'query', required: false, schema: { type: 'string' } },
            { name: 'tag', in: 'query', required: false, schema: { type: 'string' } },
          ],
          responses: {
            '200': { description: 'Plaintext', content: { 'application/json': { schema: { $ref: '#/components/schemas/Decrypted' } } } },
            '400': { description: 'decrypt_failed, invalid envelope' },
            '404': { description: 'unknown_kid: no key of yours matches the header kid' },
          },
        },
      },
    },
    components: {
      schemas: {
        Key: { type: 'object', properties: { kid: { type: 'string' }, alg: { type: 'string', enum: ['ECDH-ES'] }, jwk: { type: 'object' }, created_at: { type: 'string' }, retired_at: { type: 'string' } } },
        Decrypted: { type: 'object', properties: {
          kid: { type: 'string' }, size: { type: 'integer' },
          plaintext: { type: 'object', description: 'The message object {text, attachments[]} when the plaintext is JSON.' },
          text: { type: 'string', description: 'The plaintext as UTF-8 when it is not a JSON object.' },
          warnings: { type: 'array', items: { type: 'string' } },
        } },
      },
    },
  }
}

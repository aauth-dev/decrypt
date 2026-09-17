// OpenAPI 3.1 for the read service, served at /openapi.json (section 7a).
// A messaging service finds getKey and rotateKey here by operationId (9b).
// Host names come from env (ORIGIN, DEFAULT_RESOURCE).
import type { Env } from './types'

export function openapi(env: Pick<Env, 'ORIGIN' | 'DEFAULT_RESOURCE'>) {
  const key = { $ref: '#/components/schemas/Key' }
  const resource = { type: 'string', format: 'uri', description: `Your messaging service, as an https origin. Default ${env.DEFAULT_RESOURCE}.` }
  return {
    openapi: '3.1.0',
    info: {
      title: new URL(env.ORIGIN).host,
      version: '0.2.0',
      description:
        `A read service: holds the private keys that decrypt your end-to-end encrypted messages and reads a message for your agent. Keys are P-256 for JWE ECDH-ES with A256GCM; a message is one compact JWE. Identity is your Person Server (iss, sub), directed to this service; it never sees an address. The messaging service is \`resource\`, default ${env.DEFAULT_RESOURCE}.`,
    },
    servers: [{ url: env.ORIGIN }],
    paths: {
      '/read': {
        post: {
          operationId: 'readMessage',
          summary: `Read one message: {id} from listMessages at your messaging service. This service gets a person token for it from your Person Server over a call chain (no card), downloads the message there (which marks it downloaded), and decrypts it with your key; the JWE never passes through your agent. Returns {id, from, from_name, to, created_at, resource, kid, text, warnings}. A system message comes back as the messaging service sent it. Refusals from the messaging service pass through with step "download_message". \`resource\` defaults to ${env.DEFAULT_RESOURCE}.`,
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['id'], properties: { id: { type: 'string', description: 'The message id from listMessages.' }, resource } } } } },
          responses: {
            '200': { description: 'The message', content: { 'application/json': { schema: { $ref: '#/components/schemas/Read' } } } },
            '400': { description: 'invalid_request (id, resource)' },
            '404': { description: 'unknown_kid: no private key of yours matches the JWE kid; or not_found at the messaging service (step download_message)' },
            '422': { description: 'decrypt_failed: the JWE did not authenticate' },
            '502': { description: 'step person_token: the Person Server refused a person token for resource; or the messaging service did not answer usefully (step download_message)' },
          },
        },
      },
      '/key': {
        get: {
          operationId: 'getKey',
          summary: 'Your current public key, created if you have none. Your messaging service calls this for you over a call chain at createAccount and setServices; an agent does not need to.',
          responses: { '200': { description: 'The key', content: { 'application/json': { schema: key } } } },
        },
        post: {
          operationId: 'rotateKey',
          summary: `Mint a new key and give it to your messaging service (its setPublicKey, over a call chain), so senders use it from now on. Older keys stay: messages already sent still read. Returns the new key and the messaging service's answer. When your messaging service calls this itself (its rotatePublicKey), it stores the key and there is no call back. \`resource\` defaults to ${env.DEFAULT_RESOURCE}.`,
          requestBody: { required: false, content: { 'application/json': { schema: { type: 'object', properties: { resource } } } } },
          responses: {
            '200': { description: 'The new key; with resource and set_public_key when the agent called', content: { 'application/json': { schema: { allOf: [key, { type: 'object', properties: { resource: { type: 'string' }, set_public_key: { type: 'object', properties: { kid: { type: 'string' }, created_at: { type: 'string' } } } } }] } } } },
            '403': { description: 'not_read_service from the messaging service (step set_public_key): this is not your read service there; your key is unchanged' },
            '502': { description: 'step person_token or set_public_key: the chain failed; your key is unchanged' },
          },
        },
      },
      '/keys': {
        get: {
          operationId: 'getKeys',
          summary: 'All your keys with state, newest first.',
          responses: { '200': { description: 'Keys', content: { 'application/json': { schema: { type: 'object', properties: { keys: { type: 'array', items: key } } } } } } },
        },
      },
    },
    components: {
      schemas: {
        Key: { type: 'object', properties: { kid: { type: 'string' }, alg: { type: 'string', enum: ['ECDH-ES'] }, jwk: { type: 'object' }, created_at: { type: 'string' }, retired_at: { type: 'string' } } },
        Read: { type: 'object', properties: {
          id: { type: 'string' }, from: { type: 'string' }, from_name: { type: 'string' }, to: { type: 'string' }, created_at: { type: 'string' }, resource: { type: 'string' }, kid: { type: 'string' },
          text: { type: 'string', description: 'The message text.' },
          warnings: { type: 'array', items: { type: 'string' }, description: 'plaintext_not_json: the plaintext was not {"text": …}; text is the whole plaintext.' },
          system: { type: 'object', description: 'A system message instead of kid and text.' },
        } },
      },
    },
  }
}

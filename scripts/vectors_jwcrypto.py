# Interop vector from jwcrypto (Python): the same container from a second
# implementation. `pip install jwcrypto`, then `python3 scripts/vectors_jwcrypto.py`.
import base64, hashlib, json, os
from jwcrypto import jwk, jwe

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

key = jwk.JWK.generate(kty='EC', crv='P-256')
pub = json.loads(key.export_public())
priv = json.loads(key.export_private())
kid = b64url(hashlib.sha256(json.dumps({'crv': pub['crv'], 'kty': pub['kty'], 'x': pub['x'], 'y': pub['y']}, separators=(',', ':')).encode()).digest())

plaintext = json.dumps({
    'text': 'Hello from jwcrypto. Sphinx of black quartz, judge my vow.',
    'attachments': [{'name': 'note.md', 'media_type': 'text/markdown', 'data': base64.b64encode(b'# note\n').decode()}],
}, separators=(',', ':'))

token = jwe.JWE(plaintext.encode(), json.dumps({'alg': 'ECDH-ES', 'enc': 'A256GCM', 'kid': kid}))
token.add_recipient(key)
compact = token.serialize(compact=True)
protected, encrypted_key, iv, ciphertext, tag = compact.split('.')
assert encrypted_key == ''

vector = {
    'generator': 'jwcrypto (Python)',
    'alg': 'ECDH-ES', 'enc': 'A256GCM', 'crv': 'P-256',
    'kid': kid,
    'private_jwk': {'kty': 'EC', 'crv': 'P-256', 'x': priv['x'], 'y': priv['y'], 'd': priv['d']},
    'public_jwk': {'kty': 'EC', 'crv': 'P-256', 'x': pub['x'], 'y': pub['y']},
    'plaintext': plaintext,
    'protected': protected,
    'protected_header': json.loads(base64.urlsafe_b64decode(protected + '=' * (-len(protected) % 4))),
    'iv': iv, 'ciphertext': ciphertext, 'tag': tag,
    'compact': compact,
}
out = os.path.join(os.path.dirname(__file__), '..', 'spec', 'vectors', 'jwcrypto.json')
with open(out, 'w') as f:
    json.dump(vector, f, indent=2)
    f.write('\n')
print('wrote spec/vectors/jwcrypto.json', kid)

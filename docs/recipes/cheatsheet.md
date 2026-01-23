# Cheatsheet

This cheatsheet provides quick reference for the `joserfc` library, covering key management (JWK), signing (JWS), encryption (JWE), and tokens (JWT).

## Installation

```bash
pip install joserfc
```

## JWK (JSON Web Key)

Manage cryptographic keys.

### Import Keys

Import keys from various sources with `jwk.import_key()` method:

```python
from joserfc import jwk

# Import generic JWK (dict) - auto-detects type
key = jwk.import_key({
    "kty": "oct",
    "k": "eW91ci1zZWNyZXQta2V5", # "your-secret-key" base64url encoded
    "use": "sig"
})

# Import Symmetric Key (Oct) from string/bytes
oct_key = jwk.import_key("your-secret-key", "oct")

# Import RSA Key from PEM
pem_rsa = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlwwS7I3t2fSTawG1DcNF
Cu6NECHT3eVkr2lYXXD2hz4ILiIST2Q3/YpzNA9CrRZDseA24Ax/8UNZsMi8G1M8
Dpq1jUMKA4NrWOTrraZQmD9q4+rZLNx7M5NV8uojSoPWFYIBFwXgwzJYOZ8RVobJ
aDx6GWhWherJ1/xWrQS817mt0MwrDB9fm9RvfpBYqAKgfll6oL7MDuDTAY39yvi/
UkZGwD9b8ItdnssaiGBzqVG2inO1rUIAJ5WMK1P6K1MiSXdHRhgdSeDqMq07hFP3
IQWaOT6EWPOAEDS6E3eaHDkqNZTIrVmsVW2ScmttjRSXrmrk2U10ihiF79L9KKS/
nwIDAQAB
-----END PUBLIC KEY-----"""
rsa_key = jwk.import_key(pem_rsa, "RSA")

# Import EC Key from PEM
pem_ec = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBdy4ZhgfXuBXLWgIAVfH+qqbZ4ne
opI4cgNaZ85tQM0rzghtBbXTnP9gxj49fhos3P34nBlIdShM9vaS0yQwcA==
-----END PUBLIC KEY-----"""
ec_key = jwk.import_key(pem_rsa, "EC")

# Import OKP (Ed25519/X25519) from PEM
pem_okp = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqfwZCPkk+0u/GeXg10A3xt6JdNgqcLHqL3jKgBmL8Ow=
-----END PUBLIC KEY-----"""
okp_key = jwk.import_key(pem_okp, "OKP")
```

Import keys directly using the key type class:

```python
from joserfc.jwk import OctKey, RSAKey, ECKey, OKPKey

oct_key = OctKey.import_key("your-secret-key")

# Import RSA Key from PEM
rsa_key = RSAKey.import_key(pem_rsa)

# Import EC Key from PEM
ec_key = ECKey.import_key(pem_ec)

# Import OKP (Ed25519/X25519) from PEM
okp_key = OKPKey.import_key(pem_okp)
```

### Generate Keys

```python
from joserfc.jwk import KeyParameters
from joserfc.jwk import OctKey, RSAKey, ECKey, OKPKey

# Generate Oct (Symmetric) Key - size in bits
key = OctKey.generate_key(256) # 256 bits = 32 bytes

# Generate RSA Key
params: KeyParameters = {"use": "sig"}
rsa = RSAKey.generate_key(2048)

# Generate EC Key (P-256, P-384, P-521, secp256k1)
ec = ECKey.generate_key("P-256")

# Generate OKP Key (Ed25519, Ed448, X25519, X448)
okp = OKPKey.generate_key("Ed25519")
```

### Use KeyParameters

When importing a key, or generating a key, you can pass a `KeyParameters`
to set additional key properties.

```python
from joserfc.jwk import KeyParameters
from joserfc.jwk import OctKey, RSAKey

params: KeyParameters = {"use": "sig"}

oct_key = OctKey.import_key("your-secret-key", params)
rsa_key = RSAKey.generate_key(2048, params)
```

### Export Keys

```python
# To Dict (for JSON)
public_jwk = key.as_dict(private=False)
private_jwk = key.as_dict(private=True)

# To PEM (Asymmetric keys only)
pem_bytes = key.as_pem(private=True)
```

### Key Sets (JWKS)

```python
from joserfc.jwk import KeySet
import json

# Import from file
with open("jwks.json") as f:
    key_set = KeySet.import_key_set(json.load(f))

# Import from URL
# resp = requests.get("https://example.com/.well-known/jwks.json")
# key_set = KeySet.import_key_set(resp.json())

# Generate Key Set
key_set = KeySet.generate_key_set("EC", "P-256", count=4)
```

---

## JWS (JSON Web Signature)

Sign and verify data.

### Compact Serialization (Most Common)

```python
from joserfc import jws
from joserfc.jwk import OctKey

key = OctKey.import_key("<your-secret-key>")
payload = "hello world"

# Sign
protected = {"alg": "HS256"}
token = jws.serialize_compact(protected, payload, key)
# 'eyJ...'

# Verify
obj = jws.deserialize_compact(token, key)
print(obj.payload) # b'hello world'
print(obj.protected) # {'alg': 'HS256'}
```

### JSON Serialization (Multiple Signatures)


```python
from joserfc import jws
from joserfc.jwk import RSAKey, ECKey, KeySet

rsa_key = RSAKey.generate_key(2048)
ec_key = ECKey.generate_key("P-256")

# Create KeySet with both keys
private_key_set = KeySet([rsa_key, ec_key])

# Usually you would export the public keys and provide them to public
# through a URL such as https://example.com/jwks.json
public_jwks = private_key_set.as_dict(private=False)

payload = b"secure message"

# Sign with multiple keys
members = [
    {"protected": {"alg": "RS256"}, "header": {"kid": rsa_key.kid}},
    {"protected": {"alg": "ES256"}, "header": {"kid": ec_key.kid}}
]

# Use KeySet for private keys if multiple
value = jws.serialize_json(members, payload, private_key_set)

# Verify usually happens on the client side, clients can fetch the public keys from a URL
public_key_set = KeySet.import_key_set(public_jwks)
obj = jws.deserialize_json(value, public_key_set)
print(obj.payload) # b'secure message'
```

---

## JWE (JSON Web Encryption)

Encrypt and decrypt data.

### Compact Encryption

```python
from joserfc import jwe
from joserfc.jwk import OctKey

# Shared secret key (must match algorithm requirements)
key = OctKey.generate_key(128) # 128 bits for A128KW

protected = {"alg": "A128KW", "enc": "A128GCM"}
plaintext = "secret message"

# Encrypt
jwe_token = jwe.encrypt_compact(protected, plaintext, key)

# Decrypt
obj = jwe.decrypt_compact(jwe_token, key)
print(obj.plaintext) # b'secret message'
```

### JSON Encryption (Multiple Recipients)

```python
from joserfc import jwe
from joserfc.jwk import OctKey, RSAKey, KeySet

# General JSON Encryption builder
enc_obj = jwe.GeneralJSONEncryption({"enc": "A128GCM"}, b"payload")

# Add recipient 1
key1 = OctKey.generate_key(128)
key1.ensure_kid()
enc_obj.add_recipient({"alg": "A128KW", "kid": key1.kid})

# Add recipient 2
key2 = RSAKey.generate_key(2048)

# You use public key to encrypt and private key to decrypt
public_key = RSAKey.import_key(key2.public_key)
public_key.ensure_kid()
enc_obj.add_recipient({"alg": "RSA-OAEP", "kid": public_key.kid})

# Encrypt, we use public keys for recipients
data = jwe.encrypt_json(enc_obj, KeySet([key1, public_key]))

# Decrypt, we use private keys for decryption
obj = jwe.decrypt_json(data, KeySet([key1, key2]))
print(obj.plaintext) # b'payload'
```

---

## JWT (JSON Web Token)

Create and verify tokens with claims.

### Encode (Create Token)

```python
from joserfc import jwt
from joserfc.jwk import OctKey
import datetime

key = OctKey.import_key("secret")
header = {"alg": "HS256"}
claims = {
    "iss": "https://myapp.com",
    "sub": "user123",
    "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
}

token = jwt.encode(header, claims, key)
```

### Decode (Verify Token)

```python
# Verify and decode
# Note: decode verifies signature automatically
obj = jwt.decode(token, key)
print(obj.claims)
# {'iss': '...', 'sub': '...', 'exp': ...}
```

### Validate Claims

Use `JWTClaimsRegistry` to enforce claim rules (essential, values, format).

```python
from joserfc.jwt import JWTClaimsRegistry
from joserfc.errors import ClaimError

# Define requirements
registry = JWTClaimsRegistry(
    iss={"essential": True, "value": "https://myapp.com"},
    aud={"essential": True, "values": ["my-api", "other-api"]},
    role={"value": "admin"} # Custom claim check
)

token_obj = jwt.decode(token, key)

try:
    registry.validate(token_obj.claims)
    print("Claims valid")
except ClaimError as e:
    print(f"Validation failed: {e}")
```

### Nested JWT (JWE containing JWT)

To create an encrypted JWT, use `JWERegistry`.

```python
from joserfc import jwt, jwe
from joserfc.jwk import OctKey

key = OctKey.generate_key(128)
header = {"alg": "A128KW", "enc": "A128GCM"}
claims = {"secret": "data"}

# Pass JWERegistry to indicate JWE mode
registry = jwe.JWERegistry()
token = jwt.encode(header, claims, key, registry=registry)
```

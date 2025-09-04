<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/_static/dark-logo.svg" />
  <img alt="Authlib JOSE RFC" src="docs/_static/light-logo.svg" height="68" />
</picture>

`joserfc` is a Python library that provides a comprehensive implementation of several essential JSON Object Signing and Encryption (JOSE) standards.

[![Build Status](https://github.com/authlib/joserfc/actions/workflows/test.yml/badge.svg)](https://github.com/authlib/joserfc/actions)
[![PyPI version](https://img.shields.io/pypi/v/joserfc)](https://pypi.org/project/joserfc)
[![conda-forge version](https://img.shields.io/conda/v/conda-forge/joserfc?label=conda-forge&colorB=0090ff)](https://anaconda.org/conda-forge/joserfc)
[![PyPI Downloads](https://img.shields.io/pypi/dm/joserfc)](https://pypistats.org/packages/joserfc)
[![Code Coverage](https://codecov.io/gh/authlib/joserfc/branch/main/graph/badge.svg?token=WCD9X8HKI1)](https://codecov.io/gh/authlib/joserfc)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=authlib_joserfc&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=authlib_joserfc)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=authlib_joserfc&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=authlib_joserfc)

</div>

## Usage

A quick and simple JWT encoding and decoding would look something like this:

```python
from joserfc import jwt
from joserfc.jwk import OctKey

key = OctKey.import_key("secret")
encoded = jwt.encode({"alg": "HS256"}, {"k": "value"}, key)
# 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrIjoidmFsdWUifQ.ni-MJXnZHpFB_8L9P9yllj3RNDfzmD4yBKAyefSctMY'

token = jwt.decode(encoded, key)
print(token.header)
# {'alg': 'HS256', 'typ': 'JWT'}
print(token.claims)
# {'k': 'value'}

# validate claims (if needed)
claims_requests = jwt.JWTClaimsRegistry()
claims_requests.validate(token.claims)
```

## Features

It follows RFCs with extensible API. The module has implementations of:

- RFC7515: [JSON Web Signature](https://jose.authlib.org/en/dev/guide/jws/)
- RFC7516: [JSON Web Encryption](https://jose.authlib.org/en/dev/guide/jwe/)
- RFC7517: [JSON Web Key](https://jose.authlib.org/en/dev/guide/jwk/)
- RFC7518: [JSON Web Algorithms](https://jose.authlib.org/en/dev/guide/algorithms/)
- RFC7519: [JSON Web Token](https://jose.authlib.org/en/dev/guide/jwt/)
- RFC7520: Examples of Protecting Content Using JSON Object Signing and Encryption
- RFC7638: [JSON Web Key (JWK) Thumbprint](https://jose.authlib.org/en/guide/jwk/#thumbprint)
- RFC7797: [JSON Web Signature (JWS) Unencoded Payload Option](https://jose.authlib.org/en/dev/guide/jws/#rfc7797)
- RFC8037: ``OKP`` Key and ``EdDSA`` algorithm
- RFC8812: ``ES256K`` algorithm
- RFC9278: [JWK Thumbprint URI](https://jose.authlib.org/en/guide/jwk/#thumbprint-uri)

And draft RFCs implementation of:

- [`C20P` and `XC20P`](https://jose.authlib.org/en/dev/guide/algorithms/#c20p-and-xc20p)
- [Key Agreement with Elliptic Curve Diffie-Hellman One-Pass Unified Model](https://jose.authlib.org/en/dev/guide/algorithms/#ecdh-1pu-algorithms)
- draft-ietf-jose-deprecate-none-rsa15-02

## Useful Links

- Documentation: https://jose.authlib.org/
- Blog: https://blog.authlib.org/.
- Twitter: https://twitter.com/authlib.

## License

2023, Hsiaoming Yang. Under BSD-3 license.

<div align="center">

<img src="docs/_static/light-logo.svg" width="240" alt="Authlib JOSE RFC" />

`joserfc` is a Python library that provides a comprehensive implementation of several essential JSON Object Signing and Encryption (JOSE) standards.

[![GitHub Sponsor](https://badgen.net/badge/support/joserfc/blue?icon=github)](https://github.com/sponsors/lepture)
[![Build Status](https://github.com/authlib/joserfc/actions/workflows/test.yml/badge.svg)](https://github.com/authlib/joserfc/actions)
[![PyPI](https://badgen.net/pypi/v/joserfc)](https://pypi.org/project/joserfc)
[![Code Coverage](https://codecov.io/gh/authlib/joserfc/branch/main/graph/badge.svg?token=WCD9X8HKI1)](https://codecov.io/gh/authlib/joserfc)

</div>

## Usage

A quick and simple JWT encoding and decoding would look something like this:

```python
from joserfc import jwt

encoded = jwt.encode({"alg": "HS256"}, {"k": "value"}, "secret")
# 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrIjoidmFsdWUifQ.ni-MJXnZHpFB_8L9P9yllj3RNDfzmD4yBKAyefSctMY'

token = jwt.decode(encoded, "secret")
print(token.header)
# {'alg': 'HS256', 'typ': 'JWT'}
print(token.claims)
# {'k': 'value'}
```

## Features

It follows RFCs with extensible API. The module has implementations of:

- RFC7515: [JSON Web Signature](https://jose.authlib.org/en/latest/guide/jws/)
- RFC7516: [JSON Web Encryption](https://jose.authlib.org/en/latest/guide/jwe/)
- RFC7517: [JSON Web Key](https://jose.authlib.org/en/latest/guide/jwk/)
- RFC7518: [JSON Web Algorithms](https://jose.authlib.org/en/latest/guide/algorithms/)
- RFC7519: [JSON Web Token](https://jose.authlib.org/en/latest/guide/jwt/)
- RFC7520: Examples of Protecting Content Using JSON Object Signing and Encryption
- RFC7638: ``thumbprint`` for JWK
- RFC8037: ``OKP`` Key and ``EdDSA`` algorithm
- RFC8812: ``ES256K`` algorithm

And draft RFCs implementation of:

- [`C20P` and `XC20P`](https://jose.authlib.org/en/latest/guide/algorithms/#c20p-and-xc20p)
- [Key Agreement with Elliptic Curve Diffie-Hellman One-Pass Unified Model](https://jose.authlib.org/en/latest/guide/algorithms/#ecdh-1pu-algorithms)

## Useful Links

- Documentation: https://jose.authlib.org/
- Blog: https://blog.authlib.org/.
- Twitter: https://twitter.com/authlib.

## License

2023, Hsiaoming Yang. Under BSD-3 license.

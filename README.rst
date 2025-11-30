JOSE RFC
========

``joserfc`` is a Python library that provides a comprehensive implementation of several
essential JSON Object Signing and Encryption (JOSE) standards.

This package contains implementation of:

- RFC7515: JSON Web Signature
- RFC7516: JSON Web Encryption
- RFC7517: JSON Web Key
- RFC7518: JSON Web Algorithms
- RFC7519: JSON Web Token
- RFC7520: Examples of Protecting Content Using JSON Object Signing and Encryption
- RFC7638: JSON Web Key (JWK) Thumbprint
- RFC7797: JSON Web Signature (JWS) Unencoded Payload Option
- RFC8037: OKP Key and EdDSA algorithm
- RFC8812: ES256K algorithm
- RFC9278: JWK Thumbprint URI
- RFC9864: ``Ed25519`` and ``Ed448`` algorithms

And draft RFCs implementation of:

- draft-ietf-jose-deprecate-none-rsa15-02
- draft-amringer-jose-chacha-02
- draft-madden-jose-ecdh-1pu-04

Usage
-----

A quick and simple JWT encoding and decoding would look something like this:

.. code-block:: python

    >>> from joserfc import jwt, jwk
    >>> key = jwk.import_key("your-secret-key", "oct")
    >>> encoded_jwt = jwt.encode({"alg": "HS256"}, {"k": "value"}, key)
    >>> encoded_jwt
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrIjoidmFsdWUifQ._M8ViO_GK6TnZ9G9eqdlS7IpNWzhoGwaYYDQ3hEwwmA'
    >>> token = jwt.decode(encoded_jwt, key)
    >>> token.header
    {'alg': 'HS256', 'typ': 'JWT'}
    >>> token.claims
    {'key': 'value'}
    >>> claims_requests = jwt.JWTClaimsRegistry()
    >>> claims_requests.validate(token.claims)

Useful Links
------------

1. GitHub: https://github.com/authlib/joserfc
2. Docs: https://jose.authlib.org/en/

License
-------

Licensed under BSD. Please see LICENSE for licensing details.

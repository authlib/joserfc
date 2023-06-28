:description: Get started with joserfc module to encode and decode JSON Web Token (JWT).

Quick Start
===========

This section provides a quick overview of how to get started with ``joserfc`` and perform
encoding and decoding a JWT.

Encode and decode JWT
---------------------

.. code-block:: python

    >>> from joserfc import jwt
    >>> encoded_jwt = jwt.encode({"alg": "HS256"}, {"key": "value"}, "secret")
    >>> encoded_jwt
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJ2YWx1ZSJ9.FG-8UppwHaFp1LgRYQQeS6EDQF7_6-bMFegNucHjmWg'
    >>> token = jwt.decode(encoded_jwt, "secret")
    >>> print(token)
    {'key': 'value'}
    >>> token.header
    {'alg': 'HS256', 'typ': 'JWT'}
    >>> token.claims
    {'key': 'value'}

Learn the details of :ref:`jwt` in the next chapter.

Import and generate JWK
-----------------------

.. code-block:: python

    >>> from joserfc import jwk
    >>> rsa_key = jwk.generate_key('RSA', 512)
    >>> rsa_key.as_bytes(private=True)
    b'-----BEGIN PRIVATE KEY-----\n....'
    >>> rsa_key.as_bytes(private=False)
    b'-----BEGIN PUBLIC KEY-----\n...'
    >>> rsa_key.as_dict(private=False)
    {
      'n': 's6DoAL_A4EZ9pQFemuFtUPxjuPxyZC_1_...',
      'e': 'AQAB', 'kty': 'RSA', 'kid': 'Y9-Lx9yk...'
    }

.. code-block:: python

    >>> from joserfc import jwk
    >>> f = open("your-rsa-key.pem")
    >>> pem_data = f.read()
    >>> pem_data
    '-----BEGIN PUBLIC KEY-----\n...'
    >>> rsa_key = jwk.import_key("RSA", pem_data)
    >>> rsa_key.as_bytes()
    b'-----BEGIN PUBLIC KEY-----\n...'

Learn the details of :ref:`jwk` in the next chapter.

Next
----

Next, learn each module in details.

.. toctree::

    jwk
    jwt
    jws
    jwe

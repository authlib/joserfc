:description: Get started with joserfc module to encode and decode JSON Web Token (JWT).

Guide
=====

This section provides a quick overview of how to get started with ``joserfc`` and perform
encoding and decoding a JWT.

Encode and decode JWT
---------------------

.. code-block:: python

    >>> from joserfc import jwt
    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("secret")
    >>> encoded_jwt = jwt.encode({"alg": "HS256"}, {"key": "value"}, key)
    >>> encoded_jwt
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJ2YWx1ZSJ9.FG-8UppwHaFp1LgRYQQeS6EDQF7_6-bMFegNucHjmWg'
    >>> token = jwt.decode(encoded_jwt, key)
    >>> token.header
    {'alg': 'HS256', 'typ': 'JWT'}
    >>> token.claims
    {'key': 'value'}
    >>> claims_requests = jwt.JWTClaimsRegistry()
    >>> claims_requests.validate(token.claims)

Learn the details of :ref:`jwt` in the next chapter.

Import and generate JWK
-----------------------

.. code-block:: python

    >>> from joserfc.jwk import RSAKey
    >>> rsa_key = RSAKey.generate_key(512)
    >>> rsa_key.as_pem(private=True)
    b'-----BEGIN PRIVATE KEY-----\n....'
    >>> rsa_key.as_pem(private=False)
    b'-----BEGIN PUBLIC KEY-----\n...'
    >>> rsa_key.as_dict(private=False)
    {
      'n': 's6DoAL_A4EZ9pQFemuFtUPxjuPxyZC_1_...',
      'e': 'AQAB', 'kty': 'RSA', 'kid': 'Y9-Lx9yk...'
    }

.. code-block:: python

    >>> from joserfc.jwk import RSAKey
    >>> f = open("your-rsa-key.pem")
    >>> pem_data = f.read()
    >>> pem_data
    '-----BEGIN PUBLIC KEY-----\n...'
    >>> rsa_key = RSAKey.import_key(pem_data)
    >>> rsa_key.as_pem()
    b'-----BEGIN PUBLIC KEY-----\n...'

Learn the details of :ref:`jwk` in the next chapter.

Dive deep
---------

Next, learn each module in details.

.. grid:: 2
    :gutter: 2
    :padding: 0

    .. grid-item-card:: JSON Web Key
        :link-type: ref
        :link: jwk

        Learn how to use ``OctKey``, ``RSAKey``, ``ECKey``, ``OKPKey``, and JSON Web Key Set.

    .. grid-item-card:: JSON Web Token
        :link-type: ref
        :link: jwt

        JSON Web Token (JWT) is built on top of :ref:`jws` or :ref:`jwe`.

    .. grid-item-card:: JSON Web Signature
        :link-type: ref
        :link: jws

        Most :ref:`jwt` are encoded with JWS in compact serialization.

    .. grid-item-card:: JSON Web Encryption
        :link-type: ref
        :link: jwe

        JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.

.. toctree::
    :hidden:

    jwk
    jwt
    jws
    jwe

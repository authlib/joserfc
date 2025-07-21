:description: Usage of OctKey, RSAKey, ECKey, and OKPKey.

.. _jwk:

JSON Web Key
============

.. module:: joserfc.jwk
    :noindex:

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that
represents a cryptographic key (via RFC7517_).

.. _RFC7517: https://www.rfc-editor.org/rfc/rfc7517

.. _OctKey:

OctKey
------

An :class:`OctKey` is a symmetric key defined in
`RFC7518 section 6.4 <https://www.rfc-editor.org/rfc/rfc7518#section-6.4>`_.

Create an "oct" key
~~~~~~~~~~~~~~~~~~~

You can generate an ``OctKey`` with the :meth:`OctKey.generate_key` method:

.. code-block:: python

    from joserfc.jwk import OctKey

    key_size = 256  # in bit size, 256 equals 32 bytes
    key = OctKey.generate_key(key_size)

Import an "oct" key
~~~~~~~~~~~~~~~~~~~

You can import an ``OctKey`` from string, bytes and a JWK (in dict).

.. code-block:: python

    from joserfc.jwk import OctKey

    OctKey.import_key("a-random-string-as-key")
    OctKey.import_key(b"a-random-bytes-as-key")
    OctKey.import_key({
      "kty": "oct",
      "k": "Zm9v",
    })

When importing a key, you can add extra parameters into a key:

.. code-block:: python

    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("foo", {"use": "sig"})
    >>> key.as_dict()
    {'k': 'Zm9v', 'use': 'sig', 'kty': 'oct'}

.. _RSAKey:

RSAKey
------

An :class:`RSAKey` is an asymmetric key defined in
`RFC7518 section 6.3 <https://www.rfc-editor.org/rfc/rfc7518#section-6.3>`_.
It represents RSA keys.

Generate an "RSA" key
~~~~~~~~~~~~~~~~~~~~~

You can generate an "RSA" key with a given key size (in bit):

.. code-block:: python

    from joserfc.jwk import RSAKey

    key_size = 2048
    key = RSAKey.generate_key(key_size)

Import an "RSA" key
~~~~~~~~~~~~~~~~~~~

You can import an ``RSAKey`` from string, bytes and a JWK (in dict).

.. code-block:: python

    from joserfc.jwk import RSAKey

    pem_file = """
    -----BEGIN PUBLIC KEY-----
    MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAm0tWm31IQ3zYU27bk/NZ
    3wMJOJ+Moska3WqnptWyiVR+p/qCBlV18NUSwshoctTkETi8+HIhOjUPb0WRvQV0
    YcpsqBVdSuPZ3m4Q+uX/rudAoDKHJ6B7vwjfeg4w9aT/YF+Zi61tEy1c15rHKyXA
    HjSQGzIasOiXK1eSssim6Exx+caRL0/vWV8+0QICmEBVJiJyfDB4O3WXKac+QsI3
    LM7ZjWqQFdvx3o1v7sDycz0zdpk4qEK7hEHUsYIsyYHb70iKSkiuo3nqq2HUHklW
    y322djy/IqEq03KWuePRUZdPTDzlx5qyKpVLpMswYporngvXKpMTCal5HYfAGuYS
    MuOAVa1oL1gX8W+N4+XNrVCHSCh1JHjnO2qUT6em/HJ2gERj3kZDDfE6UXVjAw2i
    US2lP+GEim3AdUQ1jTO27Vjvuv+rNk7UjL8iDW1THlvYI9AeQnqtTTBib2b5+k6a
    8AzSPhMX/F7WP9hf0NUbkYyrJ7zRfERKqLrwpZu83PRWclnB6afPIZcN58uc+4J5
    516Ryk6PUawbBHj6zfSIDEuwKj71ki+t0GHaG4RO9QFk75ArsHWrRZNQhELBVep/
    ohwl4vscRMQFgdwdzZN8ZaaJRPFih7B+YiwIhuxpAF9fPrETa6UGoBK6MlWKE6EZ
    i5YRKx6rVWvFfMWAV3Tx9uECAwEAAQ==
    -----END PUBLIC KEY-----
    """

    RSAKey.import_key(pem_file)
    RSAKey.import_key({
        "kty": "RSA",
        "kid": "bilbo.baggins@hobbiton.example",
        "use": "sig",
        "n": "n4EPtAOCc9AlkeQHPzHSt...",
        "e": "AQAB",
        "d": "bWUC9B-...",
        "q": "uKE2dh-...",
        "dp": "B8PV...",
        "dq": "CLDm...",
        "qi": "3PiFU4..."
    })

.. _ECKey:

ECKey
-----

An :class:`ECKey` is an asymmetric key defined in
`RFC7518 section 6.2 <https://www.rfc-editor.org/rfc/rfc7518#section-6.2>`_.
It represents Elliptic Curve [DSS] keys.

Generate an "EC" key
~~~~~~~~~~~~~~~~~~~~

You can generate an "EC" key with the given curve:

.. code-block:: python

    from joserfc.jwk import ECKey

    key = ECKey.generate_key("P-256")

The "crv" values that :class:`ECKey` supports:

- ``P-256`` via RFC7518
- ``P-384`` via RFC7518
- ``P-521`` via RFC7518
- ``secp256k1`` via RFC8812

.. hint:: It is ``P-521``, not ``P-512``, it is not a typo.

Import an "EC" key
~~~~~~~~~~~~~~~~~~

You can import an ``ECKey`` from string, bytes and a JWK (in dict).

.. code-block:: python

    from joserfc.jwk import ECKey

    pem_file = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIBnRS4Tf1PY6Jb7QOwAM7OWUOMJTBenEWRvGBCGgctBfoAoGCCqGSM49
    AwEHoUQDQgAE3r15c+Yd+0GXKysfWtwkqF7k12ylNE9LdfRP4TfkUcJSQXyGQjcx
    U8E81rOHjo+9xv2e64n4X6pC3yuP+pX4eA==
    -----END EC PRIVATE KEY-----
    """

    ECKey.import_key(pem_file)
    ECKey.import_key({
        "kty": "EC",
        "crv": "P-256",
        "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
        "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
        "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
    })

.. _OKPKey:

OKPKey
------

An :class:`OKPKey` is an asymmetric key defined in RFC8037_
CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in
JSON Object Signing and Encryption (JOSE).

.. _RFC8037: https://www.rfc-editor.org/rfc/rfc8037#section-2

Generate an "OKP" key
~~~~~~~~~~~~~~~~~~~~~

You can generate an "OKP" key with the given curve:

.. code-block:: python

    from joserfc.jwk import OKPKey

    key = OKPKey.generate_key("Ed25519")

:class:`OKPKey` accepts "crv" values of ``Ed25519``, ``Ed448``,
``X25519``, and ``X448``.

Import an "OKP" key
~~~~~~~~~~~~~~~~~~~

You can import an ``OKPKey`` from string, bytes and a JWK (in dict).

.. code-block:: python

    from joserfc.jwk import OKPKey

    pem_file = """
    -----BEGIN PRIVATE KEY-----
    MEcCAQAwBQYDK2VxBDsEOaVsPKMXOBfq9aHlDEaMlBY+FR63hwrINHa2X74uHXUr
    3/VXE8eMhrr8stXn41CQKqVmFEeL5Uj5Gg==
    -----END PRIVATE KEY-----
    """

    OKPKey.import_key(pem_file)
    OKPKey.import_key({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "t-nFRaxyM5DZcpg5lxiEeJcZpMRB8JgcKaQC0HRefXU",
        "d": "gUF17HCe-pbN7Ej2rDSXl-e7uSj7rQW5u2dNu0KINP0",
        "kid": "5V_IcL-iX5IbaNz9vg0CjXtWLZiJ94-ESnHI-HN1L2Y"
    })

Key Set
-------

A JWK Set is a JSON object that represents a set of JWKs. An example
of a JWK Set:

.. code-block:: none

    {"keys": [
        {
            "kty":"EC",
            "crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1"
        },
        {
            "kty":"RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
            "e":"AQAB",
            "alg":"RS256",
            "kid":"2011-04-29"
        }
    ]}

Create a key set
~~~~~~~~~~~~~~~~

You can create a key set with a given set of keys:

.. code-block:: python

    from joserfc.jwk import KeySet

    key_set = KeySet([rsa_key1, rsa_key2, ec_key1])

Or, you can generate a key set for a certain "kty":

.. code-block:: python

    key_set = KeySet.generate_key_set("EC", "P-256", count=4)

Import a key set
~~~~~~~~~~~~~~~~

An example about importing JWKS from a local file:

.. code-block:: python

    import json

    with open("your-jwks.json") as f:
        data = json.load(f)
        key_set = KeySet.import_key_set(data)

An example about importing JWKS from a URL:

.. code-block:: python

    import requests

    resp = requests.get("https://example.com/jwks.json")
    key_set = KeySet.import_key_set(resp.json())

Key methods
-----------

.. _thumbprint:

``thumbprint``
~~~~~~~~~~~~~~

Calling this method will generate the thumbprint of the JWK, per RFC7638.

.. code-block:: python

    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.generate_key()
    >>> key.thumbprint()
    'DCdRGGDKvhAJgmVlCp6tosc2T9ELtd30S_15vn8bhrI'

You can also use the ``jwk.thumbprint`` method:

.. code-block:: python

    from joserfc import jwk
    jwk.thumbprint({
        'kty': 'oct',
        'k': 'sTBpI_oCHSyW-n0exSwhzNHwU9FGRioPauxWA84bnRU',
    })
    # 'DCdRGGDKvhAJgmVlCp6tosc2T9ELtd30S_15vn8bhrI'


``thumbprint_uri``
~~~~~~~~~~~~~~~~~~

.. versionadded:: 1.2.0

Calling this method will generate the JWK thumbprint URI, per RFC9278.

.. code-block:: python

    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.generate_key()
    >>> key.thumbprint_uri()
    'urn:ietf:params:oauth:jwk-thumbprint:sha-256:DCdRGGDKvhAJgmVlCp6tosc2T9ELtd30S_15vn8bhrI'

You can also use the ``jwk.thumbprint_uri`` method:

.. code-block:: python

    from joserfc import jwk
    jwk.thumbprint_uri({
        'kty': 'oct',
        'k': 'sTBpI_oCHSyW-n0exSwhzNHwU9FGRioPauxWA84bnRU',
    })
    # 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:DCdRGGDKvhAJgmVlCp6tosc2T9ELtd30S_15vn8bhrI'

.. _ensure_kid:

``ensure_kid``
~~~~~~~~~~~~~~

Call this method to make sure the key contains a ``kid``. If the key has no
``kid``, generate one with the above ``.thumbprint`` method.

.. code-block:: python

    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("foo")
    >>> key.kid
    None
    >>> key.ensure_kid()
    >>> key.kid
    '8-e-qGDS2nDpfZzOPtD8Sb7NkifUbw70MeqOKIqyaRw'

``as_dict``
~~~~~~~~~~~

Dump a key or key set into dict format, which can be used to convert to JSON:

.. code-block:: python

    data = key.as_dict(private=False)  # dump as a public key
    # data = key.as_dict(private=True)  # dump as a private key
    with open("my-key.json", "w") as f:
        json.dump(data, f)

``as_pem``
~~~~~~~~~~

Dump an asymmetric key into PEM format (in bytes):

.. code-block:: python

    # text = key.as_pem(private=False)  # dump as a public key
    text: bytes = key.as_pem(private=True)  # dump as a private key

    with open("my-key.pem", "w") as f:
        f.write(text)

``as_der``
~~~~~~~~~~

Dump an asymmetric key into DER format (in bytes):

.. code-block:: python

    # text = key.as_der(private=False)  # dump as a public key
    text: bytes = key.as_der(private=True)  # dump as a private key

    with open("my-key.der", "w") as f:
        f.write(text)

Utilities
---------

The ``jwk`` module offers a means to dynamically import and generate keys.

Import keys
~~~~~~~~~~~

.. versionadded:: v1.1.0

The :meth:`import_key` can choose the correct key type automatically when
importing a JWK in dict:

.. code-block:: python

    from joserfc import jwk

    data = {"kty": "oct", "k": "..."}
    key = jwk.import_key(data)  # returns a OctKey

    data = {"kty": "RSA", ...}
    key = jwk.import_key(data)  # returns a RSAKey

    data = {"kty": "EC", ...}
    key = jwk.import_key(data)  # returns a ECKey

    data = {"kty": "OKP", ...}
    key = jwk.import_key(data)  # returns a OKPKey

If the key is in bytes or string, not dict, developers SHOULD specify
the key type manually:

.. code-block:: python

    data = b"---- BEGIN RSA PRIVATE KEY ----\n..."
    key = jwk.import_key(data, "RSA")


Generate keys
~~~~~~~~~~~~~

.. versionadded:: v1.1.0

The :meth:`generate_key` can generate a key with all the supported key
types. For ``oct`` and ``RSA`` the parameters in this method:

.. code-block:: python

    from joserfc import jwk

    # (key_type: str, size: int, parameters: Optional[dict], private: bool=True)
    key = jwk.generate_key("oct", 256)
    key = jwk.generate_key("RSA", 2048, {"use": "sig"})

For ``EC`` and ``OKP`` keys, the parameters are:

.. code-block:: python

    # (key_type: str, crv: str, parameters: Optional[dict], private: bool=True)
    key = jwk.generate_key("EC", "P-256")
    key = jwk.generate_key("OKP", "Ed25519")


Options
-------

The ``import_key`` and ``generate_key`` methods available on ``OctKey``, ``RSAKey``,
``ECKey``, ``OKPKey``, and ``jwk`` classes have an optional ``parameters`` parameter.
This ``parameters`` allows you to provide a dict that includes additional key parameters
to be included in the JWK.

Some of the standard (registered) header fields are:

- ``kty``: Key Type, it is automatically added
- ``use``: Public Key Use, "sig" or "enc"
- ``key_ops``: Key Operations, allowed operations of this key
- ``alg``: Algorithm, allowed algorithm of this key
- ``kid``: Key ID, a string of the key ID

When using ``import_key`` and ``generate_key``, developers can pass the extra key ``parameters``:

.. code-block:: python

    parameters = {"use": "sig", "alg": "RS256", "key_ops": ["verify"]}
    RSAKey.import_key(data, parameters=parameters)

The above ``RSAKey`` then can only be used for ``JWS`` with ``alg`` of ``RS256``, and it can
only be used for deserialization (``verify``).

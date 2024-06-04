Migrating from Authlib
======================

``joserfc`` is derived from Authlib and shares similar implementations
of algorithms. However, it is important to note that the APIs are different
between the two libraries. When migrating your code from Authlib to ``joserfc``,
you will need to update your code to accommodate the new API structure
and functionality.

JWT
---

Migrating JWT (JSON Web Token) operations from Authlib to ``joserfc`` involves
some considerations regarding security design and the allowed algorithms.

jwt.encode
~~~~~~~~~~

The interface for JWT operations in both ``authlib.jose`` and ``joserfc`` is quite similar.
In both libraries, you can encode a JWT using the ``jwt.encode(header, payload, key)`` method.

.. code-block:: python
    :caption: Authlib

    from authlib.jose import jwt

    jwt.encode({"alg": "HS256"}, {"iss": "https://jose.authlib.org"}, "secret")


.. code-block:: python
    :caption: joserfc

    from joserfc import jwt
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")
    jwt.encode({"alg": "HS256"}, {"iss": "https://jose.authlib.org"}, key)

jwt.decode
~~~~~~~~~~

The ``jwt.decode`` method in Authlib and ``joserfc`` behaves differently when it
comes to claims validation.

In Authlib, the ``jwt.decode`` method combines the decoding of the JWT and the
validation of its claims into a single step.

.. code-block:: python

    from authlib.jose import jwt

    s = '...'  # The JWT to decode
    # Decode and validate the token's claims
    token = jwt.decode(s, key, claims_options)

In ``joserfc``, the ``jwt.decode`` process is split into two steps: decoding the
token and then separately validating its claims. This approach provides more
flexibility and allows for granular control over the validation process.

.. code-block:: python

    from joserfc import jwt

    s = '...'  # The JWT to decode
    token = jwt.decode(s, key)

    claims_requests = jwt.JWTClaimsRegistry(
        iss={"essential": True, "value": "https://authlib.org"},
    )
    claims_requests.validate(token.claims)

You can learn more about :ref:`claims validation <claims>` on the :ref:`jwt` guide.

JWS
---

When migrating JWS (JSON Web Signature) operations from Authlib to ``joserfc``,
follow these steps:

.. code-block:: python
    :caption: Authlib
    :emphasize-lines: 1,2

    from authlib.jose import JsonWebSignature
    jws = JsonWebSignature()

    protected = {'alg': 'HS256'}
    payload = b"example"
    value = jws.serialize_compact(protected, payload, "secret")
    jws.deserialize_compact(value, "secret")

.. code-block:: python
    :caption: joserfc

    from joserfc import jws
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")
    protected = {"alg': 'HS256"}
    payload = b"example"
    value = jws.serialize_compact(protected, payload, key)
    jws.deserialize_compact(value, key)

Above is a simple example of using the ``HS256`` algorithm for JWS. If you would like
to explore further and learn more about JWS, we recommend referring to the comprehensive
:ref:`jws` guide.

JWE
---

The method names for JWE serialization and deserialization are different
between Authlib and ``joserfc``.

In Authlib, the methods for JWE serialization and deserialization are:

- ``.serialize_compact(header, payload, key)``
- ``.deserialize_compact(token, key)``

.. code-block:: python

    from authlib.jose import JsonWebEncryption

    jwe = JsonWebEncryption()
    jwe.serialize_compact(header, payload, key)
    jwe.deserialize_compact(token, key)

In ``joserfc``, the equivalent methods for JWE serialization and deserialization are:

- ``.encrypt_compact(header, payload, key)``
- ``.decrypt_compact(token, key)``

.. code-block:: python

    from joserfc import jwe

    jwe.encrypt_compact(header, payload, key)
    jwe.decrypt_compact(token, key)

If you would like to explore further and learn more about JWS, we recommend referring to
the comprehensive :ref:`jwe` guide.

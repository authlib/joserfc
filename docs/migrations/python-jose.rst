Migrating from python-jose
==========================

``python-jose`` supports all JOSE specifications, similar to ``joserfc``.
However, there are significant differences in code structure, method names,
and parameter usage. Additionally, ``joserfc`` offers built-in Python type
hints, enhancing code readability and type safety.

Another key difference is that ``python-jose`` only supports compact serialization
and deserialization, whereas ``joserfc`` supports both compact and JSON serialization
formats, offering greater flexibility in handling JOSE data.

JWS
---

In ``python-jose``, the methods used for serialization and deserialization are
``jws.sign`` and ``jws.verify``, respectively.

On the other hand, ``joserfc`` uses ``jws.serialize_compact`` for serialization
and ``jws.deserialize_compact`` for deserialization.

.. code-block:: python
    :caption: python-jose

    from jose import jws

    signed = jws.sign({'a': 'b'}, 'secret', algorithm='HS256')
    jws.verify(signed, 'secret', algorithms='HS256')
    # the verify only returns the payload

.. code-block:: python
    :caption: joserfc

    import json
    from joserfc import jws
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")
    protected = {"alg": "HS256"}
    signed = jws.serialize_compact(protected, json.dumps({'a': 'b'}), key)
    obj = jws.deserialize_compact(text, key)
    # access the payload with obj.payload

.. important::

    ``joserfc`` is designed to be highly explicit, requiring the use of specific
    key types, payload formats, and other components. For example, in the previous
    example, we explicitly use an OctKey instead of a simple string. Additionally,
    since JWS in joserfc only supports encoding strings and bytes, you cannot pass
    a dictionary directly as the payload. Instead, the payload must first be converted
    to a JSON string using json.dumps. This explicit approach ensures better type
    safety and clarity in your code.

JWE
---

In ``python-jose``, the methods used for encryption and decryption are ``jwe.encrypt``
and ``jwe.decrypt``. However, since ``joserfc`` supports both compact and JSON serialization
formats, it provides distinct methods: ``jwe.encrypt_compact`` and ``jwe.decrypt_compact`` for
compact serialization, ensuring clear differentiation between the formats and greater
flexibility in handling JWE operations.

.. code-block:: python
    :caption: python-jose

    from jose import jwe

    encrypted = jwe.encrypt('Hello, World!', 'asecret128bitkey', algorithm='dir', encryption='A128GCM')
    jwe.decrypt(encrypted, 'asecret128bitkey')
    # => 'Hello, World!'

.. code-block:: python
    :caption: joserfc

    from joserfc import jwe
    from joserfc.jwk import OctKey

    key = OctKey.generate_key(128)  # 128bit key
    protected = {'alg': 'dir', 'enc': 'A128GCM'}
    encrypted = jwe.encrypt_compact(protected, 'Hello, World!', key)
    obj = jwe.decrypt_compact(encrypted, key)
    # obj.payload => b'Hello, World!'

JWT
---

The ``jwt`` module in ``python-jose`` supports only JWS (JSON Web Signature) mode,
whereas ``joserfc`` provides support for both JWS and JWE (JSON Web Encryption) modes.
Although both libraries utilize the ``encode`` and ``decode`` methods, their parameters
differ significantly in terms of structure and flexibility.

.. code-block:: python
    :caption: python-jose

    from jose import jwt

    encoded = jwt.encode({'a': 'b'}, 'secret', algorithm='HS256')
    jwt.decode(encoded, 'secret', algorithms='HS256')
    # => {'a': 'b'}

.. code-block:: python
    :caption: joserfc

    from joserfc import jwt
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")
    # jwt.encode(header, payload, key)
    encoded = jwt.encode({"alg": "HS256"}, {'a': 'b'}, key)
    token = jwt.decode(encoded, key)
    # => token.header : {"alg": "HS256"}
    # => token.claims : {"a": "b"}

``get_unverified_header``
~~~~~~~~~~~~~~~~~~~~~~~~~

The ``jwt`` module in python-jose provides a method called ``get_unverified_header``,
which allows extracting the header from a JWT without verifying its signature.

In ``joserfc``, we can get the unverified header with:

.. code-block:: python
    :caption: joserfc

    from typing import Any
    from joserfc import jws

    def get_unverified_header(token: str) -> dict[str, Any]:
        obj = jws.extract_compact(token.encode())
        return obj.protected

``get_unverified_claims``
~~~~~~~~~~~~~~~~~~~~~~~~~

You can also use the ``jws.extract_compact`` method to extract the JWT's claims:

.. code-block:: python
    :caption: joserfc

    import json
    from typing import Any
    from joserfc import jws

    def get_unverified_claims(token: str) -> dict[str, Any]:
        obj = jws.extract_compact(token.encode())
        return json.loads(obj.payload)

JWK
---

In ``python-jose``, you can use ``jwk.construct`` to create a key instance
from a JWK-formatted dictionary. In contrast, ``joserfc`` provides the
``jwk.import_key`` method to achieve the same result.

.. code-block:: python
    :caption: joserfc

    from joserfc import jwk

    jwk.import_key({
        "kty": "oct",
        "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
        "use": "sig",
        "alg": "HS256",
        "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
    })

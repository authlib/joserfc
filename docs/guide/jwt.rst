:description: How to encode and decode a JSON Web Token (JWT) in python.

.. _jwt:

JSON Web Token
==============

.. module:: joserfc.jwt
    :noindex:

JSON Web Token (JWT) is built on top of :ref:`jws` or :ref:`jwe` and includes
specific payload claims. These claims are required to be in JSON format and
follow a predefined set of fields.

.. hint::

    Do you know that JSON Web Token (JWT) is not a part of JOSE. Instead,
    it was created by the OAuth working group.

Encode token
------------

:meth:`encode` is the method for creating a JSON Web Token string.
It encodes the payload with the given ``alg`` in header:

.. code-block:: python

    from joserfc import jwt
    from joserfc.jwk import OctKey

    header = {"alg": "HS256"}
    claims = {"iss": "https://authlib.org"}
    key = OctKey.import_key("secret")
    text = jwt.encode(header, claims, key)

The returned value of ``text`` in above example is:

.. code-block:: none

    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
    eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIn0.
    Zm430u0j1wzf5Me5Zoj2h6dTt9IFsb7-G5mUW3BTWbo

Line breaks for display only.

Prevent sensitive data leaks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before calling :meth:`encode` on your claims, it's a good practice to ensure
they do not contain sensitive information, such as credit card numbers.

You can use :meth:`check_sensitive_data` to detect whether sensitive data is
present in the claims:

.. code-block:: python

    from joserfc import jwt

    jwt.check_sensitive_data(claims)

Decode token
------------

:meth:`decode` is the method to translate a JSON Web Token string
into a token object which contains ``.header`` and ``.claims`` properties:

.. code-block:: python

    # reuse the text and key in above example
    token = jwt.decode(text, key)
    # token.header = {'alg': 'HS256', 'typ': 'JWT'}
    # token.claims = {"iss": "https://authlib.org"}

.. _claims:

Validate claims
---------------

The ``jwt.decode`` method will only verify if the payload is a JSON
base64 string.

You can define claims requests :class:`JWTClaimsRegistry` for validating the
decoded claims. The ``JWTClaimsRegistry`` accepts each claim as an
`Individual Claims Requests <http://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests>`_
JSON object.

.. code-block:: python

    from joserfc.jwt import JWTClaimsRegistry

    claims_requests = JWTClaimsRegistry(
        iss={"essential": True, "value": "https://authlib.org"},
    )

    # usually you will use the claims registry after ``.decode``
    claims_requests.validate(token.claims)

The Individual Claims Requests JSON object contains:

``essential``
  OPTIONAL. Indicates whether the Claim being requested is an Essential Claim.
  If the value is true, this indicates that the Claim is an Essential Claim.

``value``
  OPTIONAL. Requests that the Claim be returned with a particular value.

``values``
  OPTIONAL. Requests that the Claim be returned with one of a set of values,
  with the values appearing in order of preference.

And we added one more field:

``allow_blank``
  OPTIONAL. Allow essential claims to be an empty string.

Missing essential claims
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    claims_requests = JWTClaimsRegistry(aud={"essential": True})

    # this will raise MissingClaimError
    claims = {"iss": "https://authlib.org"}
    claims_requests.validate(claims)

    # this will raise MissingClaimError
    claims = {"iss": ""}
    claims_requests.validate(claims)

Allow empty essential claims
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    claims_requests = JWTClaimsRegistry(aud={"essential": True, "allow_blank": True})

    # this will NOT raise MissingClaimError
    claims = {"iss": ""}
    claims_requests.validate(claims)

Invalid claims values
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    claims = {"iss": "https://authlib.org"}
    claims_requests = JWTClaimsRegistry(iss={"value": "https://jose.authlib.org"})

    claims_requests.validate(claims)  # this will raise InvalidClaimError

Default validators
~~~~~~~~~~~~~~~~~~

The ``JWTClaimsRegistry`` has built-in validators for timing related fields:

- ``exp``: expiration time
- ``nbf``: not before
- ``iat``: issued at

List validation
~~~~~~~~~~~~~~~

When validating claims that contain lists, the registry checks if **any** of the
required values are present in the claim's list. This behavior is designed for
flexible authorization checks where matching any of the required permissions grants
access. For single values, it checks for an exact match.

This is particularly useful for validating role based or permission based claims. For
example:

.. code-block:: python

    # Claim containing a list of permissions
    claims = {"permissions": ["users:read", "users:write", "users:admin"]}

    # Passes since "users:write" is present in the list
    claims_requests = JWTClaimsRegistry(
        permissions={"values": ["users:write", "system:admin"]}
    )
    claims_requests.validate(claims)

    # Raises InvalidClaimError since none of the required values are present
    claims_requests = JWTClaimsRegistry(
        permissions={"values": ["system:admin"]}
    )
    claims_requests.validate(claims)

You can also validate against a single required value:

.. code-block:: python

    # Claim containing a list of permissions
    claims = {"permissions": ["users:read", "users:write", "users:admin"]}

    # Passes since "users:read" is present in the list
    claims_requests = JWTClaimsRegistry(
        permissions={"value": "users:read"}
    )
    claims_requests.validate(claims)

Custom validation
-----------------

When it's not possible to validate a claim using ``ClaimsOption``,
you can define a custom validation method named ``validate_{name}``.
For example, if the claims must include a ``source`` field, and the
value of ``source`` must be an HTTPS URL, you can implement a custom
method to enforce this requirement.

.. code-block:: python

    from joserfc.jwt import JWTClaimsRegistry
    from joserfc.errors import InvalidClaimError

    class MyClaimsRegistry(JWTClaimsRegistry):
        def validate_source(self, value):
            if not value.startswith('https://'):
                raise InvalidClaimError('source')

Then, you can validate the claims with:

.. code-block:: python

    claims_requests = MyClaimsRegistry(source={"essential": True})

JWS & JWE
---------

JWT is built on top of JWS and JWE, all of the above examples are in JWS. By default
``jwt.encode`` and ``jwt.decode`` work for **JWS**. To use **JWE**, you need to specify
a ``registry`` parameter with ``JWERegistry``. Here is an example of JWE:

.. code-block:: python

    from joserfc import jwt, jwe
    from joserfc.jwk import OctKey

    header = {"alg": "A128KW", "enc": "A128GCM"}
    claims = {"iss": "https://authlib.org"}
    key = OctKey.generate_key(128)  # the algorithm requires key of 128 bit size
    registry = jwe.JWERegistry()  # YOU MUST USE A JWERegistry
    jwt.encode(header, claims, key, registry=registry)

The JWE formatted result contains 5 parts, while JWS only contains 3 parts,
a JWE example would be something like this (line breaks for display only):

.. code-block:: none

    eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwidHlwIjoiSldUIn0.
    F3plSTFE5GPJNs_qGsmoVx4o402URh5G.
    57P7XX6C3hJbk-Nl.
    dpgaZFi3uI1RiOqI3bmYY3_opkljIwcByf_j6fM.
    uv1BZZy5F-ci54BS11EYGg

Another difference is the key used for ``encode`` and ``decode``.

For :ref:`jws`, a private key is used for ``encode``, and a public key is used for
``decode``. The ``encode`` method will use a private key to sign, and the ``decode``
method will use a public key to verify.

For :ref:`jwe`, it is the contrary, a public key is used for ``encode``, and a private
key is used for ``decode``. The ``encode`` method  will use a public key to encrypt,
and the ``decode`` method will use a private key to decrypt.

The key parameter
-----------------

In the above example, we're using :ref:`OctKey` only for simplicity. There are other
types of keys in :ref:`jwk`.

Key types
~~~~~~~~~

Each algorithm (``alg`` in header) requires a certain type of key. For example:

- ``HS256`` requires ``OctKey``
- ``RS256`` requires ``RSAKey``
- ``ES256`` requires ``ECKey`` or ``OKPKey``

You can find the correct key type for each algorithm at:

- :ref:`JSON Web Signature Algorithms <jws_algorithms>`
- :ref:`JSON Web Encryption Algorithms <jwe_algorithms>`

Here is an example of a JWT with "alg" of ``RS256`` in JWS type:

.. code-block:: python

    from joserfc import jwt
    from joserfc.jwk import RSAKey

    header = {"alg": "RS256"}
    claims = {"iss": "https://authlib.org"}
    with open("your-private-rsa-key.pem") as f:
        key = RSAKey.import_key(f.read())

    # "RS256" is a recommended algorithm, no need to pass a custom ``registry``
    text = jwt.encode(header, claims, key)

    # ``.encode`` for JWS type use a public key, if using a private key,
    # it will automatically extract the public key from private key
    jwt.decode(text, key)

In production, ``jwt.encode`` is usually used by the *client* side, a client
normally does not have the access to private keys. The server provider would
usually expose the public keys in JWK Set.

Use key set
~~~~~~~~~~~

You can also pass a JWK Set to the ``key`` parameter of :meth:`encode` and
:meth:`decode` methods.

.. code-block:: python

    import json
    from joserfc.jwk import KeySet
    from joserfc import jwt

    with open("your-private-jwks.json") as f:
        data = json.load(f)
        key_set = KeySet.import_key_set(data)

    header = {"alg": "RS256", "kid": "1"}
    claims = {"iss": "https://authlib.org"}
    jwt.encode(header, claims, key_set)

The methods will find the correct key according to the ``kid`` you specified.
If there is no ``kid`` in header, it will pick one randomly and add the ``kid``
of the key into header.

A client would usually get the public key set from a public URL, normally the
``decode`` code would be something like:

.. code-block:: python

    import requests
    from joserfc import jwt
    from joserfc.jwt import Token
    from joserfc.jwk import KeySet

    resp = requests.get("https://example-site/jwks.json")
    key_set = KeySet.import_key_set(resp.json())

    def parse_token(token_string: str) -> Token:
        return jwt.decode(token_string, key_set)

Callable key
~~~~~~~~~~~~

It is also possible to assign a callable function as the ``key``:

.. code-block:: python

    import json
    from joserfc.jwk import KeySet
    from joserfc.jws import CompactSignature

    def load_key(obj: CompactSignature) -> KeySet:
        headers = obj.headers()
        alg = headers["alg"]
        key_path = f"my-{alg}-keys.json"
        with open(key_path) as f:
            data = json.load(f)
            return KeySet.import_key_set(data)

    # jwt.encode(header, claims, load_key)

Embedded JWK
~~~~~~~~~~~~

The key may be embedded directly in the token's header. For example,
the decoded header might look like this:

.. code-block:: json

    {
      "jwk": {
        "crv": "P-256",
        "x": "UM9g5nKnZXYovWAlM76cLz9vTozRj__CHU_dOl-gOoE",
        "y": "ds8aeQw1l2cDCA7bCkONvwDKpXAbtXjvqCleYH8Ws_U",
        "kty": "EC"
      },
      "alg": "ES256"
    }

In such cases, you don't need to supply a separate key manually. Instead,
as shown above, you can use a callable key function to dynamically
resolve the embedded JWK value.

.. code-block:: python

    from joserfc import jwk

    def embedded_jwk(obj: jwk.GuestProtocol) -> jwk.Key:
        headers = obj.headers()
        return jwk.import_key(headers["jwk"])

    # jwt.decode(value, embedded_jwk)

Embedded JWK Set URL
~~~~~~~~~~~~~~~~~~~~

As shown above, the key may also be provided as a JWK Set URL
within the token header, for example:

.. code-block:: json

    {
      "jku": "https://example-site/jwks.json",
      "alg": "ES256"
    }

In this case, you can use a callable key function to import the
JWKs:

.. code-block:: python

    import requests
    from joserfc.jwk import GuestProtocol, Key, KeySet

    def fetch_jwk_set(obj: GuestProtocol) -> Key:
        headers = obj.headers()
        resp = requests.get(headers["jku"])
        return KeySet.import_key_set(resp.json())

    jwt.decode(value, fetch_jwk_set)

.. hint::

    Use a cache method to improve the performance.

Algorithms & Registry
---------------------

The :meth:`encode` and :meth:`decode` accept an ``algorithms`` parameter for
specifying the allowed algorithms. By default, it only allows you to use the
**recommended** algorithms.

You can find out the recommended algorithms at:

- :ref:`JSON Web Signature Algorithms <jws_algorithms>`
- :ref:`JSON Web Encryption Algorithms <jwe_algorithms>`

For instance, ``HS384`` is not a recommended algorithm, and you want to use
this algorithm:

.. code-block:: python

    >>> from joserfc import jwt, jwk
    >>> header = {"alg": "HS384"}
    >>> claims = {"iss": "https://authlib.org"}
    >>> key = jwk.OctKey.import_key("secret")
    >>> jwt.encode(header, claims, key, algorithms=["HS384"])

If not specifying the ``algorithms`` parameter, the ``encode`` method will
raise an error.

JSON Encoder and Decoder
------------------------

.. versionadded:: 1.1.0

    The parameters ``encoder_cls`` for ``jwt.encode`` and ``decoder_cls`` for ``jwt.decode``
    were introduced in version 1.1.0.

When using ``jwt.encode`` to encode claims that contain data types that ``json``
module does not natively support, such as ``UUID`` and ``datetime``, an error will
be raised.

.. code-block:: python

    >>> import uuid
    >>> from joserfc import jwt, jwk
    >>>
    >>> key = jwk.OctKey.import_key("secret")
    >>> claims = {"sub": uuid.uuid4()}
    >>> jwt.encode({"alg": "HS256"}, claims, key)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File ".../joserfc/jwt.py", line 66, in encode
        payload = convert_claims(claims, encoder_cls)
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      File ".../joserfc/rfc7519/claims.py", line 36, in convert_claims
        content = json.dumps(claims, ensure_ascii=False, separators=(",", ":"), cls=encoder_cls)
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      File ".../lib/python3.12/json/__init__.py", line 238, in dumps
        **kw).encode(obj)
              ^^^^^^^^^^^
      File ".../lib/python3.12/json/encoder.py", line 200, in encode
        chunks = self.iterencode(o, _one_shot=True)
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      File ".../lib/python3.12/json/encoder.py", line 258, in iterencode
        return _iterencode(o, 0)
               ^^^^^^^^^^^^^^^^^
      File ".../lib/python3.12/json/encoder.py", line 180, in default
        raise TypeError(f'Object of type {o.__class__.__name__} '
    TypeError: Object of type UUID is not JSON serializable

To resolve this issue, you can pass a custom ``JSONEncoder`` using the ``encoder_cls`` parameter.

.. code-block:: python

    import uuid
    import json
    from joserfc import jwt, jwk

    class MyEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, uuid.UUID):
                return str(o)
            return super().default(o)

    key = jwk.OctKey.import_key("secret")
    claims = {"sub": uuid.uuid4()}
    jwt.encode({"alg": "HS256"}, claims, key, encoder_cls=MyEncoder)

Additionally, ``jwt.decode`` accepts a ``decoder_cls`` parameter. If you need to convert
the decoded claims into the appropriate data types, you can provide a custom decoder class.

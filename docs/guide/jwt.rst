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
`Individual Claims Requests <ClaimsOption>`_ JSON object.

.. _ClaimsOption: http://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests

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
If there is no ``kid`` in header, it will pick on randomly and add the ``kid``
of the key into header.

A client would usually get the public key set from a public URL, normally the
``decode`` code would be something like:

.. code-block:: python

    import requests
    from joserfc import jwt
    from joserfc.jwk import KeySet

    resp = requests.get("https://example.com/.well_known/jwks.json")
    key_set = KeySet.import_key_set(resp.json())

    def parse_token(token_string: str):
        jwt.decode(token_string, key_set)

Callable key
~~~~~~~~~~~~

It is also possible to assign a callable function as the ``key``:

.. code-block:: python

    import json
    from joserfc import jwk

    def load_key(obj):
        headers = obj.headers()
        alg = headers["alg"]
        key_path = f"my-{alg}-key.json"
        with open(key_path) as f:
            data = json.load(f)
            key = jwk.import_key(data["kty"], data)
        return key

    # jwt.encode(header, claims, load_key)

Algorithms & Registry
---------------------

The :meth:`encode` and :meth:`decode` accept an ``algorithms`` parameter for
specifying the allowed algorithms. By default, it only allows your to use
recommended algorithms.

You can find out the recommended algorithms at:

- :ref:`JSON Web Signature Algorithms <jws_algorithms>`
- :ref:`JSON Web Encryption Algorithms <jwe_algorithms>`

For instance, ``HS386`` is not a recommended algorithm, and you want to use
this algorithm:

.. code-block:: python

    >>> from joserfc import jwt, jwk
    >>> header = {"alg": "HS384"}
    >>> claims = {"iss": "https://authlib.org"}
    >>> key = jwk.OctKey.import_key("secret")
    >>> jwt.encode(header, claims, key, algorithms=["HS384"])

If not specifying the ``algorithms`` parameter, the ``encode`` method will
raise an error.

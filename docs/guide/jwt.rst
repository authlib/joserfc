.. _jwt:

JSON Web Token
==============

.. module:: joserfc.jwt
    :noindex:

JSON Web Token (JWT) is built on top of :ref:`jws` or :ref:`jwe` with certain payload claims.
The claims should be in JSON format, with specified fields.

.. hint::

    Do you know JWT is not a part of JOSE. It is created by the OAuth working group.

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

The returned value of ``text `` in above example is:

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

Missing essential claims
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    claims = {"iss": "https://authlib.org"}
    claims_requests = JWTClaimsRegistry(aud={"essential": True})

    claims_requests.validate(claims)  # this will raise MissingClaimError

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

JWT is built on top of JWS and JWE, all of the above examples are in JWS. Here
is an example of JWE:

.. code-block:: python

    from joserfc import jwt
    from joserfc.jwk import OctKey

    header = {"alg": "A128KW", "enc": "A128GCM"}
    claims = {"iss": "https://authlib.org"}
    key = OctKey.generate_key(128)  # the algorithm requires key of 128 bit size
    jwt.encode(header, claims, key)

The JWE formatted result contains 5 parts, while JWS only contains 3 parts,
a JWE example would be something like this:

.. code-block:: none

    eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwidHlwIjoiSldUIn0.
    F3plSTFE5GPJNs_qGsmoVx4o402URh5G.
    57P7XX6C3hJbk-Nl.
    dpgaZFi3uI1RiOqI3bmYY3_opkljIwcByf_j6fM.
    uv1BZZy5F-ci54BS11EYGg

**line breaks for display only**

Another difference is the key used for ``encode`` and ``decode``.

For :ref:`jws`, a private key is used for ``encode``, and a public key is used for
``decode``. The ``encode`` method will use a private key to sign, and the ``decode``
method will use a public key to verify.

For :ref:`jwe`, it is the contrary, a public key is used for ``encode``, and a private
key is used for ``decode``. The ``encode`` method  will use a public key to encrypt,
and the ``decode`` method will use a private key to decrypt.

Keys
----

In the above example, we're using :ref:`OctKey` only simplicity. There are other
types of keys in :ref:`jwk`.

Correct keys
~~~~~~~~~~~~

Each algorithm (``alg`` in header) requires a certain type of key. For example,
``HS256`` requires ``OctKey``, while ``RS256`` requires :ref:`RSAKey`.


Use key set
~~~~~~~~~~~

Callable key
~~~~~~~~~~~~

Algorithms & Registry
---------------------

Extract token
-------------

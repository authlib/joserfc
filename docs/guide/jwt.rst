.. _jwt:

JSON Web Token
==============

JSON Web Token (JWT) is built on top of :ref:`jws` or :ref:`jwe`. It defines claims
in JSON to represent the payload (or plaintext).

.. hint::

    Do you know JWT is not a part of JOSE. It is created by the OAuth working group.

Encode & decode
---------------

Encode token
~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jwt
    from joserfc.jwk import OctKey

    header = {"alg": "HS256"}
    claims = {"sub": "https://authlib.org"}
    key = OctKey.import_key("__secret_key__")
    jwt.encode(header, claims, key)

Decode token
~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jwt
    from joserfc.jwk import OctKey

    text = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJodHRwczovL2F1dGhsaWIub3JnIn0.oBboiOm3vb8048O3cexjIDBikTG2Yju9mChBciif-g4'
    key = OctKey.import_key("__secret_key__")
    token = jwt.decode(text, key)
    # token.header = {'alg': 'HS256', 'typ': 'JWT'}
    # token.claims = {"sub": "https://authlib.org"}

Validate claims
~~~~~~~~~~~~~~~

JWS & JWE
---------

Advanced usage
--------------

Extract token
~~~~~~~~~~~~~

Use registry
~~~~~~~~~~~~

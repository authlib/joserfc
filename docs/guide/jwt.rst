.. _jwt:

JSON Web Token
==============

Encode token
------------

.. code-block:: python

    from joserfc import jwt
    from joserfc.jwk import OctKey

    header = {"alg": "HS256"}
    claims = {"sub": "https://authlib.org"}
    key = OctKey.import_key("__secret_key__")
    jwt.encode(header, claims, key)

Decode token
------------

Extract token
-------------

Use registry
------------

Algorithms
~~~~~~~~~~

Claims validator
~~~~~~~~~~~~~~~~

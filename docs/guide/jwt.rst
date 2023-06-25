.. _jwt:

JSON Web Token
==============

JSON Web Token (JWT) is a kind of :ref:`jws`, it defines

.. hint::

    Do you know JWT is not a part of JOSE. It is created by the OAuth working group.

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

Validate claims
---------------

Use registry
------------

Algorithms
~~~~~~~~~~

Claims validator
~~~~~~~~~~~~~~~~

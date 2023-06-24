JOSE RFC
========

``joserfc`` is a Python implementation of **JSON Object Signing and Encryption** (JOSE).
It follows RFCs with extensible API. The module has implementations of:

- RFC7515: :ref:`JSON Web Signature <jws>`
- RFC7516: :ref:`JSON Web Encryption <jwe>`
- RFC7517: :ref:`JSON Web Key <jwk>`
- RFC7518: :ref:`JSON Web Algorithms <jwa>`
- RFC7519: :ref:`JSON Web Token <jwt>`
- RFC7638: ``thumbprint`` for JWK
- RFC8037: ``OKP`` Key and ``EdDSA`` algorithm
- RFC8812: ``ES256K`` algorithm

And draft RFCs implementation of:

- :ref:`chacha20`
- :ref:`ecdh1pu`

**This package is a part of the Authlib project.**

Features
--------

- Type hints

Usage
-----

A quick and simple JWT encoding and decoding would look something like this:

.. code-block:: python

    >>> from joserfc import jwt
    >>> encoded = jwt.encode({"alg": "HS256"}, {"k": "value"}, "secret")
    >>> encoded
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrIjoidmFsdWUifQ.ni-MJXnZHpFB_8L9P9yllj3RNDfzmD4yBKAyefSctMY'
    >>> token = jwt.decode(encoded, "secret")
    >>> token.header
    {'alg': 'HS256', 'typ': 'JWT'}
    >>> token.claims
    {'k': 'value'}

You would find more details and advanced usage in :ref:`jwt` section.

Next
----

Explore the following sections to discover more about our theme and its features.

.. toctree::
   :caption: Getting started
   :hidden:

   install
   guide/introduction

.. toctree::
   :caption: Essentials
   :hidden:

   guide/index
   guide/algorithms
   guide/registry
   migrations/index

.. toctree::
   :caption: Recipes
   :hidden:

   recipes/azure
   recipes/openssl


.. toctree::
   :caption: Development
   :hidden:

   api
   security
   stability
   contributing/index
   changelog

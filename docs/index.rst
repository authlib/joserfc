JOSE RFC
========

``joserfc`` is a Python library that provides a comprehensive implementation of
several essential JSON Object Signing and Encryption (JOSE) standards, including
JWS (JSON Web Signature), JWE (JSON Web Encryption), JWK (JSON Web Key),
JWA (JSON Web Algorithms), and JWT (JSON Web Tokens).

It is derived from Authlib_, but features a redesigned API specific to JOSE functionality.

.. _Authlib: https://authlib.org/

Usage
-----

A quick and simple JWT encoding and decoding would look something like this:

.. code-block:: python

    >>> from joserfc import jwt
    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("secret")
    >>> encoded = jwt.encode({"alg": "HS256"}, {"k": "value"}, key)
    >>> encoded
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrIjoidmFsdWUifQ.ni-MJXnZHpFB_8L9P9yllj3RNDfzmD4yBKAyefSctMY'
    >>> token = jwt.decode(encoded, key)
    >>> token.header
    {'alg': 'HS256', 'typ': 'JWT'}
    >>> token.claims
    {'k': 'value'}

You would find more details and advanced usage in :ref:`jwt` section.

.. important::

    The string ``"secret"`` employed in the above example is solely intended for demonstration
    purposes. In a production environment, it is crucial to use a highly secure secret key to
    ensure robust security measures.

RFCs
----

It follows RFCs with extensible API. The module has implementations of:

- RFC7515: :ref:`JSON Web Signature <jws>`
- RFC7516: :ref:`JSON Web Encryption <jwe>`
- RFC7517: :ref:`JSON Web Key <jwk>`
- RFC7518: :ref:`JSON Web Algorithms <jwa>`
- RFC7519: :ref:`JSON Web Token <jwt>`
- RFC7520: Examples of Protecting Content Using JSON Object Signing and Encryption
- RFC7638: ``thumbprint`` for JWK
- RFC7797: JSON Web Signature (JWS) :ref:`Unencoded Payload Option <rfc7797>`
- RFC8037: :ref:`OKPKey` and ``EdDSA`` algorithm
- RFC8812: ``ES256K`` algorithm
- RFC9278: JWK Thumbprint URI (``thumbprint_uri``)

And draft RFCs implementation of:

- :ref:`chacha20`
- :ref:`ecdh1pu`

.. hint:: RFC7520 is implemented as test cases.

Next
----

Explore the following sections to discover more about ``joserfc`` and its features.

.. toctree::
   :caption: Getting started
   :hidden:

   guide/introduction
   install

.. toctree::
   :caption: Essentials
   :hidden:

   guide/index
   guide/algorithms
   guide/registry
   guide/errors
   migrations/index

.. toctree::
   :caption: Recipes
   :hidden:

   recipes/azure
   recipes/openssl


.. toctree::
   :caption: Development
   :hidden:

   api/index
   security
   stability
   contributing/index
   changelog

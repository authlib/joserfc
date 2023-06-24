:description: All available algorithms for JWS, JWE, JWK, JWT.

Algorithms
==========

JWS and JWT
-----------

JSON Web Token (JWT) is a kind of JSON Web Signature (JWS),
they share the same algorithms. Here lists all the available
algorithms for JWS and JWT.

- HS256

Recommended algorithms
~~~~~~~~~~~~~~~~~~~~~~

JSON Web Key
------------

"oct" algorithm
~~~~~~~~~~~~~~~

"RSA" algorithm
~~~~~~~~~~~~~~~

"EC" algorithm
~~~~~~~~~~~~~~

"OKP" algorithm
~~~~~~~~~~~~~~~

JSON Web Encryption
-------------------

Default "alg" values
~~~~~~~~~~~~~~~~~~~~

Default "enc" values
~~~~~~~~~~~~~~~~~~~~

C20P and XC20P
~~~~~~~~~~~~~~

``C20P`` and ``XC20P`` algorithms are still in drafts, they are not registered by default.
To use ``C20P`` and ``XC20P``, developers have to install the ``PyCryptodome`` module.XC20P

.. code-block:: shell

    pip install pycryptodome

This is caused by ``cryptography`` package does only support "ChaCha20" cipher, while
``pycryptodome`` supports both "ChaCha20" and "XChaCha20" ciphers.

Register ciphers
++++++++++++++++

The default :ref:`registry` doesn't contain draft ciphers, developers MUST register
``C20P`` and ``XC20P`` at first:

.. code-block:: python

    from joserfc.jwe import JWERegistry
    from joserfc.drafts.jwe_chacha20 import C20P, XC20P

    JWERegistry.register(C20P)
    JWERegistry.register(XC20P)

Use custom ``registry``
+++++++++++++++++++++++

.. automodule:: joserfc.jwe
    :noindex:

Use a custom ``registry`` in :meth:`encrypt_compact`, :meth:`decrypt_compact`,
:meth:`encrypt_json`, and :meth:`decrypt_json`.

.. code-block:: python

    from joserfc import jwe
    from joserfc.jwk import OctKey

    registry = JWERegistry(
        # add more "alg" and "enc" if you want
        algorithms=["A128KW", "C20P"]
    )

    key = OctKey.generate_key(128)  # A128KW requires 128 bits key
    protected = {"alg": "A128KW", "enc": "C20P"}
    encrypted_text = jwe.encrypt_compact(
        protected,
        b"hello",
        public_key=key,
        registry=registry,
    )

ECDH-1PU algorithms
~~~~~~~~~~~~~~~~~~~

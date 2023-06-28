:description: All available algorithms for JWS, JWE, JWK, JWT.

.. _jwa:

Algorithms
==========

This documentation describes the algorithms to be used with
JSON Web Signature (JWS), JSON Web Encryption (JWE), and
JSON Web Key (JWK).

JSON Web Key
------------

The JSON Web Key (JWK) algorithms contains:

- :ref:`OctKey`
- :ref:`RSAKey`
- :ref:`ECKey`
- :ref:`OKPKey`

.. _jws_algorithms:

JSON Web Signature
------------------

``joserfc.jws`` module supports algorithms from RFC7518, RFC8037,
and RFC8812. You MUST specify the correct key type for each algorithm.

============== ========== ==================
Algorithm name Key Type      Recommended
============== ========== ==================
none           OctKey      :bdg-danger:`No`
HS256          OctKey      :bdg-success:`Yes`
HS384          OctKey      :bdg-danger:`No`
HS512          OctKey      :bdg-danger:`No`
RS256          RSAKey      :bdg-success:`Yes`
RS384          RSAKey      :bdg-danger:`No`
RS512          RSAKey      :bdg-danger:`No`
ES256          ECKey       :bdg-success:`Yes`
ES384          ECKey       :bdg-danger:`No`
ES512          ECKey       :bdg-danger:`No`
PS256          RSAKey      :bdg-danger:`No`
PS384          RSAKey      :bdg-danger:`No`
PS512          RSAKey      :bdg-danger:`No`
EdDSA          OKPKey      :bdg-danger:`No`
ES256K         ECKey       :bdg-danger:`No`
============== ========== ==================

.. _jwe_algorithms:

JSON Web Encryption
-------------------

``joserfc.jwe`` module supports algorithms from RFC7518, and drafts of
``ECDH-1PU``. You MUST specify the correct key type for each algorithm.

===================  ==========  ==================
Algorithm name       Key Type    Recommended
===================  ==========  ==================
dir                  OctKey      :bdg-success:`Yes`
A128KW               OctKey      :bdg-success:`Yes`
A192KW               OctKey      :bdg-danger:`No`
A256KW               OctKey      :bdg-success:`Yes`
RSA1_5               RSAKey      :bdg-danger:`No`
RSA-OAEP             RSAKey      :bdg-success:`Yes`
RSA-OAEP-256         RSAKey      :bdg-danger:`No`
ECDH-ES              ECKey       :bdg-success:`Yes`
ECDH-ES+A128KW       ECKey       :bdg-success:`Yes`
ECDH-ES+A192KW       ECKey       :bdg-danger:`No`
ECDH-ES+A256KW       ECKey       :bdg-success:`Yes`
A128GCMKW            OctKey      :bdg-danger:`No`
A192GCMKW            OctKey      :bdg-danger:`No`
A256GCMKW            OctKey      :bdg-danger:`No`
PBES2-HS256+A128KW   RSAKey      :bdg-danger:`No`
PBES2-HS384+A192KW   RSAKey      :bdg-danger:`No`
PBES2-HS512+A256KW   RSAKey      :bdg-danger:`No`
===================  ==========  ==================

All algorithms defined in RFC7518 for "enc" value are recommended, which
including:

- A128CBC-HS256
- A192CBC-HS384
- A256CBC-HS512
- A128GCM
- A192GCM
- A256GCM

A ``DEF`` algorithm for the "zip" (compression) header parameter is also defined in
RFC7518, which is recommended.

There are also additional algorithms for "alg" and "enc" in draft versions.
Please refer to the following sections for more information.


OKPKey
~~~~~~

You can use ``OKPKey`` with the "crv" (curve) parameter set to ``X25519`` or ``X448``
for the following algorithms:

- "ECDH-ES"
- "ECDH-ES+A128KW"
- "ECDH-ES+A192KW"
- "ECDH-ES+A256KW"

This allows you to utilize these elliptic curve algorithms with ``OKPKey`` for your
cryptographic operations.

.. _chacha20:

C20P and XC20P
~~~~~~~~~~~~~~

``C20P`` and ``XC20P`` algorithms are still in drafts, they are not registered by default.
To use ``C20P`` and ``XC20P``, developers have to install the ``PyCryptodome`` module.

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

.. module:: joserfc.jwe
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

.. _ecdh1pu:

ECDH-1PU algorithms
~~~~~~~~~~~~~~~~~~~

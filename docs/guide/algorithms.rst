:description: All available algorithms for JWS, JWE, JWK, and JWT.

.. _jwa:

Algorithms
==========

.. rst-class:: lead

    All available algorithms for JWS, JWE, JWK, and JWT.

-----

This documentation describes the algorithms to be used with
JSON Web Signature (JWS), JSON Web Encryption (JWE), and
JSON Web Key (JWK).

JSON Web Key
------------

The JSON Web Key (JWK) algorithms contains:

- :ref:`OctKey` : accepts key size in bits, which means the ``key_size`` MUST be dividable by 8.
- :ref:`RSAKey` : accepts key size in bits, ``key_size`` MUST ``>=512`` and dividable by 8.
- :ref:`ECKey` : accepts ``crv`` with ``P-256``, ``P-384``, ``P-521``, and ``secp256k1``.
- :ref:`OKPKey` : accepts ``crv`` with ``Ed25519``, ``Ed448``, ``X25519``, and ``X448``.

.. _jws_algorithms:

JSON Web Signature
------------------

``joserfc.jws`` module supports algorithms from RFC7518, RFC8037,
and RFC8812. You MUST specify the correct key type for each algorithm.

============== ========== ============================
Algorithm name Key Type      Requirements
============== ========== ============================
none           OctKey      :bdg-danger:`Deprecated`
HS256          OctKey      :bdg-success:`Recommended`
HS384          OctKey      :bdg-muted:`Optional`
HS512          OctKey      :bdg-muted:`Optional`
RS256          RSAKey      :bdg-success:`Recommended`
RS384          RSAKey      :bdg-muted:`Optional`
RS512          RSAKey      :bdg-muted:`Optional`
ES256          ECKey       :bdg-success:`Recommended`
ES384          ECKey       :bdg-muted:`Optional`
ES512          ECKey       :bdg-muted:`Optional`
PS256          RSAKey      :bdg-muted:`Optional`
PS384          RSAKey      :bdg-muted:`Optional`
PS512          RSAKey      :bdg-muted:`Optional`
EdDSA          OKPKey      :bdg-muted:`Optional`
ES256K         ECKey       :bdg-muted:`Optional`
============== ========== ============================

.. note::
    ``EdDSA`` algorithm only accepts ``OKPKey`` with "crv" of "Ed25519" and "Ed448".

By default, JWS ``serialize`` and ``deserialize`` methods will ONLY allow recommended
algorithms. To use non-recommended algorithms, developers MUST explicitly specify the
algorithms either by the ``algorithms`` parameter, or ``registry`` parameter.

.. code-block:: python

    from joserfc import jws
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")
    # HS384 is a non-recommended algorithm
    jws.serialize_compact({"alg": "HS384"}, b"payload", key, algorithms=["HS384"])

    # or with a custom registry
    registry = jws.JWSRegistry(algorithms=["HS384"])
    jws.serialize_compact({"alg": "HS384"}, b"payload", key, registry=registry)

.. warning::
    ``none`` algorithm is deprecated via https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/

.. _jwe_algorithms:

JSON Web Encryption
-------------------

``joserfc.jwe`` module supports algorithms from RFC7518, and drafts of
``ECDH-1PU``. You MUST specify the correct key type for each algorithm.

===================  ==========  ===========================
Algorithm name       Key Type    Requirements
===================  ==========  ===========================
dir                  OctKey      :bdg-success:`Recommended`
A128KW               OctKey      :bdg-success:`Recommended`
A192KW               OctKey      :bdg-muted:`Optional`
A256KW               OctKey      :bdg-success:`Recommended`
RSA1_5               RSAKey      :bdg-danger:`Deprecated`
RSA-OAEP             RSAKey      :bdg-success:`Recommended`
RSA-OAEP-256         RSAKey      :bdg-muted:`Optional`
ECDH-ES              ECKey       :bdg-success:`Recommended`
ECDH-ES+A128KW       ECKey       :bdg-success:`Recommended`
ECDH-ES+A192KW       ECKey       :bdg-muted:`Optional`
ECDH-ES+A256KW       ECKey       :bdg-success:`Recommended`
A128GCMKW            OctKey      :bdg-muted:`Optional`
A192GCMKW            OctKey      :bdg-muted:`Optional`
A256GCMKW            OctKey      :bdg-muted:`Optional`
PBES2-HS256+A128KW   RSAKey      :bdg-muted:`Optional`
PBES2-HS384+A192KW   RSAKey      :bdg-muted:`Optional`
PBES2-HS512+A256KW   RSAKey      :bdg-muted:`Optional`
===================  ==========  ===========================

All algorithms defined in RFC7518 for "enc" value are recommended, which
including:

- ``A128CBC-HS256``
- ``A192CBC-HS384``
- ``A256CBC-HS512``
- ``A128GCM``
- ``A192GCM``
- ``A256GCM``

.. warning::
    ``RSA1_5`` algorithm is deprecated via https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/

There is also a ``DEF`` algorithm for the "zip" (compression) header parameter,
using of ``DEF`` is optional.

There are also additional algorithms for "alg" and "enc" in draft versions.
Please refer to the following sections for more information.

OKPKey
~~~~~~

You can use ``OKPKey`` with the "crv" (curve) parameter set to ``X25519`` or ``X448``
for the following algorithms:

- ECDH-ES
- ECDH-ES+A128KW
- ECDH-ES+A192KW
- ECDH-ES+A256KW

This allows you to utilize these elliptic curve algorithms with ``OKPKey`` for your
cryptographic operations.

.. _chacha20:

C20P and XC20P
~~~~~~~~~~~~~~

``C20P`` and ``XC20P`` algorithms are still in drafts, they are not registered by default.
To use ``C20P`` and ``XC20P``, developers have to install the ``PyCryptodome`` module.

.. code-block:: shell

    pip install pycryptodome

This is caused by ``cryptography`` package does only support "ChaCha20" cipher, not **XChaCha20**,
while ``pycryptodome`` supports both "ChaCha20" and "XChaCha20" ciphers.

Register ciphers
++++++++++++++++

The default :ref:`registry` doesn't contain draft ciphers, developers MUST register
``C20P`` and ``XC20P`` at first:

.. code-block:: python

    from joserfc.drafts.jwe_chacha20 import register_chacha20_poly1305

    register_chacha20_poly1305()

Use custom ``registry``
+++++++++++++++++++++++

.. module:: joserfc.jwe
    :noindex:

Use a custom ``registry`` in :meth:`encrypt_compact`, :meth:`decrypt_compact`,
:meth:`encrypt_json`, and :meth:`decrypt_json`.

.. code-block:: python

    from joserfc import jwe
    from joserfc.jwk import OctKey

    registry = jwe.JWERegistry(
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

Key Agreement with Elliptic Curve Diffie-Hellman One-Pass Unified Model (ECDH-1PU)
are still in drafts, they are not registered by default. To use ``ECDH-1PU`` related
algorithms, developers MUST register them manually:

.. code-block:: python

    from joserfc.drafts.jwe_ecdh_1pu import register_ecdh_1pu

    register_ecdh_1pu()

Then use a custom ``registry`` with the required ``ECDH-1PU`` algorithms. For instance:

.. code-block:: python

    from joserfc import jwe
    from joserfc.jwk import ECKey

    registry = jwe.JWERegistry(
        algorithms=["ECDH-1PU+A128KW", "A128CBC-HS256"]
    )
    protected = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256"}
    recipient_key = ECKey.import_key("your-ec-public-key.json")
    sender_key = ECKey.import_key("your-ec-sender-key.json")  # this SHOULD be a private key
    encrypted_text = jwe.encrypt_compact(
        protected,
        b"hello",
        public_key=recipient_key,
        registry=registry,
        sender_key=sender_key,
    )

.. important::

    The ``ECDH-1PU`` algorithms require a **sender key**, which MUST be a private key when
    calling :meth:`encrypt_compact` and :meth:`encrypt_json` methods.

The ``sender_key`` can be a :class:`~joserfc.jwk.KeySet`, and JWE will find the correct key
according to ``skid`` header value.

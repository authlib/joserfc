Changelog
=========

.. rst-class:: lead

    Here is the history of joserfc_ package releases.

.. _joserfc: https://pypi.org/project/joserfc/

----

.. module:: joserfc
    :noindex:

1.3.4
-----

**Released on September 21, 2025**

- Add size limit for deserializing JWS content.
- Add size limit for decrypting JWE content.


1.3.3
-----

**Released on September 15, 2025**

- Reject ``crit`` header in unprotected headers.

1.3.2
-----

**Released on September 4, 2025**

- Returns the first key when multiple keys found in a key set.
- Validate if a "crit" header is supported in the registry.

1.3.1
-----

**Released on August 27, 2025**

- Fix ``jws.deserialize_json`` and ``jwe.decrypt_json``, preventing unprotected header
  overwriting protected header.

1.3.0
-----

**Released on August 25, 2025**

- Exporting all algorithms in ``joserfc.jwa`` module.
- Allow reusing ``JWTClaimsRegistry`` instance, via :issue:`68`.
- Added ``claim`` attribute on claim errors, via :issue:`69`.
- Added ``JWSRegistry.guess_alg`` method, via :issue:`49`.

**Breaking changes**:

- Remove Python 3.8 support.
- Rename JWS and JWE Algorithm model class names to prevent name conflicts.


1.2.2
-----

**Released on July 14, 2025**

- Fix typo for function name of Chacha20-Poly1305 registration, via :pull:`67`.
- Add claims partial list matching in ``JWTClaimRegistry.validate``, via :pull:`63`.

1.2.1
-----

**Released on July 10, 2025**

- Improve type hints on JWK module:
  - Overload type hints on ``jwk.import_key`` and ``jwk.generate_key``.
  - Return correct types on ``OctKey.import_key``, ``RSAKey.import_key``, and etc.
- Guess key with "alg" and "use" parameters.

1.2.0
-----

**Released on July 7, 2025**

- Added RFC9278 JWK Thumbprint URI ``thumbprint_uri``.
- Show security warnings for ``none`` and ``RSA1_5`` algorithms.
- Show security warnings for ``OctKey.generate_key`` and ``RSAKey.generate_key``.
  when key size is too short, per `NIST SP 800-131A`_.

.. _`NIST SP 800-131A`: https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final

**Breaking changes**:

- Enable "RFC7797" by default, use the ``joserfc.jws`` module directly.
  - Use ``joserfc.jws.serialize_compact`` instead of ``joserfc.rfc7797.serialize_compact``
  - Use ``joserfc.jws.deserialize_compact`` instead of ``joserfc.rfc7797.deserialize_compact``
  - Use ``joserfc.jws.serialize_json`` instead of ``joserfc.rfc7797.serialize_json``
  - Use ``joserfc.jws.deserialize_json`` instead of ``joserfc.rfc7797.deserialize_json``
- Convert ``joserfc.rfcXXXX`` to private modules ``joserfc._rfcXXXX``.

1.1.0
-----

**Released on May 24, 2025**

- Use "import as" to prioritize the modules for editors.
- Added parameter ``encoder_cls`` for ``jwt.encode`` and ``decoder_cls`` for ``jwt.decode``.
- Added ``none`` algorithm for JWS.
- Added ``jwk.import_key`` and ``jwk.generate_key`` aliases.

**Breaking changes**:

- Use ``ECKey.binding.register_curve`` to register new supported curves.
- Use ``UnsupportedAlgorithmError`` instead of ``ValueError`` in JWS/JWE registry.
- Use ``MissingKeyTypeError`` and ``InvalidKeyIdError`` for errors in JWK.
- Use ``UnsupportedHeaderError``, ``MissingHeaderError``, and ``MissingCritHeaderError`` for header validation.
- Respect RFC6749 character set in error descriptions.

1.0.4
-----

**Released on February 28, 2025**

- Use secrets module to generate random bytes.
- Use warnings for possible unsafe ``OctKey`` instead of raising error, via :issue:`32`.

1.0.3
-----

**Released on February 6, 2025**

- Allow using sha256, sha384, sha512 hash functions in thumbprint (RFC7638).

1.0.2
-----

**Released on January 20, 2025**

- Support import key from a certificate pem file.

1.0.1
-----

**Released on December 3, 2024**

- Throw an error on non-valid base64 strings.

1.0.0
-----

**Released on July 14, 2024**

- Fix type hints for strict mode.

0.12.0
------

**Released on June 15, 2024**

- Limit DEF decompress size to 250k bytes.
- Fix claims validation, via :issue:`23`.

0.11.1
------

**Released on June 4, 2024**

- Remove validating ``typ`` header with ``jwt.decode`` method.

0.11.0
------

**Released on June 4, 2024**

- ``jwe.decrypt_json`` allows to verify only one recipient.
- Prevent ``OctKey`` to import ``ssh-dss``.
- Deprecate use of string and bytes as key.

0.10.0
------

**Released on May 13, 2024**

- Change ``jwt.encode`` and ``jwt.decode`` to use JWS by default.

0.9.0
-----

**Released on November 16, 2023**

- Use ``os.urandom`` for ``OctKey.generate_key``.
- Add ``allow_blank`` for ``JWTClaimsRegistry``.
- Improve callable key for :meth:`~jwk.guess_key`.

0.8.0
-----

**Released on September 06, 2023**

- Add :ref:`ensure_kid` method on key models.
- Add ``auto_kid`` parameter on key model ``.generate_key`` method.
- Improvements on type hints

0.7.0
-----

**Released on August 14, 2023**

- Add "iat" claims validation in JWT.
- Add ``__bool__`` magic method on :class:`jwk.KeySet`.
- Raise ``InvalidExchangeKeyError`` for ``exchange_derive_key`` on Curve key.
- Improvements on type hints

0.6.0
-----

**Released on July 20, 2023**

- Huge improvements on type hints, via :user:`Viicos`.
- Do not mutate the header when ``jwt.encode``, via :issue:`6`.
- Register algorithms with their matched key types on key set.
- Improve error handling, raise proper errors.

**Breaking changes**:

- ``jws.JSONSignature`` is replaced by :class:`jws.GeneralJSONSignature`
  and :class:`jws.FlattenedJSONSignature`.
- ``jwe.JSONEncryption`` is replaced by :class:`jwe.GeneralJSONEncryption`
  and :class:`jwe.FlattenedJSONEncryption`.

0.5.0
-----

**Released on July 12, 2023**

- Add RFC7797 JSON Web Signature (JWS) Unencoded Payload Option
- Fix ``decrypt_json`` when there is no ``encrypted_key``
- Rename JWE CompleteJSONSerialization to GeneralJSONSerialization
- Rename ``JSONEncryption.flatten`` to ``.flattened``
- Load and dump RSA, EC, and OKP key with password
- Rename Curve key method: ``exchange_shared_key`` to ``exchange_derive_key``

0.4.0
-----

**Released on July 6, 2023**

- Change ``options`` to ``parameters`` for JWK methods
- Change ``JWSRegistry`` and ``JWERegistry`` parameters
- Guess ``sender_key`` from JWKs in JWE
- Add importing key from DER encoding bytes
- Fix JWS JSON serialization when members have only unprotected headers
- Check key type before processing algorithms of JWS and JWE

0.3.0
-----

**Released on June 29, 2023**

- Return ``str`` instead of ``bytes`` for JWS and JWE serializations
- Add a ``detach_content`` method for JWS
- Remove ``jwt.extract`` method, because ``extract`` won't work for JWE
- Add ``JWKRegistry`` for JWK
- Update ``JSONEncryption.add_recipient`` parameters
- Export register methods for JWE drafts

0.2.0
-----

**Released on June 25, 2023**

A beta release.

0.1.0
-----

**Released on March 5, 2023**

Initial release.

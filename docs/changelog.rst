Changelog
=========

.. rst-class:: lead

    Here is the history of joserfc_ package releases.

.. _joserfc: https://pypi.org/project/joserfc/

----

.. module:: joserfc
    :noindex:

0.12.0
------

**Released on June 15, 2024**

- Limit DEF decompress size to 250k bytes.
- Fix claims validation, , via :issue:`23`.

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

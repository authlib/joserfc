Changelog
=========

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

**Released on Mar 5, 2023**

Initial release.

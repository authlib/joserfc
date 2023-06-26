API References
==============

JSON Web Signature
------------------

.. module:: joserfc.jws

.. autoclass:: JWSRegistry

.. autoclass:: JWSAlgModel

.. autoclass:: CompactSignature

.. autoclass:: JSONSignature

.. autofunction:: serialize_compact

.. autofunction:: extract_compact

.. autofunction:: validate_compact

.. autofunction:: deserialize_compact

.. autofunction:: serialize_json

.. autofunction:: extract_json

.. autofunction:: validate_json

.. autofunction:: deserialize_json

.. autofunction:: detach_content


JSON Web Encryption
-------------------

.. module:: joserfc.jwe

.. autofunction:: encrypt_compact

.. autofunction:: decrypt_compact

.. autofunction:: encrypt_json

.. autofunction:: decrypt_json


JSON Web Key
------------

.. module:: joserfc.jwk

.. autoclass:: OctKey

.. autoclass:: RSAKey

.. autoclass:: ECKey

.. autoclass:: OKPKey

.. autoclass:: KeySet

.. autofunction:: generate_key

.. autofunction:: import_key

.. autofunction:: guess_key

.. autoclass:: SymmetricKey

.. autoclass:: AsymmetricKey

.. autoclass:: CurveKey

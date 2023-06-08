API References
==============

JSON Web Signature
------------------

.. module:: joserfc.jws

.. autofunction:: serialize_compact

.. autofunction:: extract_compact

.. autofunction:: validate_compact

.. autofunction:: deserialize_compact

.. autofunction:: serialize_json

.. autofunction:: extract_json

.. autofunction:: validate_json

.. autofunction:: deserialize_json

.. autoclass:: JWSRegistry

.. autoclass:: JWSAlgModel

JSON Web Key
------------

.. module:: joserfc.jwk

.. autoclass:: SymmetricKey

.. autoclass:: AsymmetricKey

.. autoclass:: CurveKey

.. autoclass:: OctKey

.. autoclass:: RSAKey

.. autoclass:: ECKey

.. autoclass:: OKPKey

.. autoclass:: KeySet

.. autofunction:: generate_key

.. autofunction:: import_key

.. autofunction:: guess_key

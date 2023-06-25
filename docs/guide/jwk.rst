.. _jwk:

JSON Web Key
============

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that
represents a cryptographic key. (via RFC7517_)

.. _RFC7517: https://www.rfc-editor.org/rfc/rfc7517

OctKey
------

Create an "oct" key
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from joserfc.jwk import OctKey

    key_size = 256  # in bit size, 256 equals 32 bytes
    key = OctKey.generate_key(key_size)

RSAKey
------

ECKey
-----

OKPKey
------

Key Set
-------

Utilities
---------

``generate_key``
~~~~~~~~~~~~~~~~

``import_key``
~~~~~~~~~~~~~~

``guess_key``
~~~~~~~~~~~~~

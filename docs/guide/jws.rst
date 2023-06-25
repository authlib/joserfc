.. _jws:

JSON Web Signature
==================

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JSON-based
data structures. (via RFC7515_)

.. _RFC7515: https://www.rfc-editor.org/rfc/rfc7515

Compact Signature
-----------------

The JWS Compact Serialization represents digitally signed or MACed
content as a compact, URL-safe string. This string is:

.. code-block:: text

    BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    BASE64URL(JWS Payload) || '.' ||
    BASE64URL(JWS Signature)

An example of a compact serialization:

.. code-block:: text

    eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
    dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

.. note:: line breaks for display purposes only

Serialization
~~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jws

    header = {"alg": "HS256"}
    jws.serialize_compact(header, b"hello", "secret")
    # => b'eyJhbGciOiJIUzI1NiJ9.aGVsbG8.UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A'

Deserialization
~~~~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jws

    text = "eyJhbGciOiJIUzI1NiJ9.aGVsbG8.UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A"
    obj = jws.deserialize_compact(text, "secret")
    # => obj.payload == b"hello"

JSON Signature
--------------

Serialization
~~~~~~~~~~~~~

Deserialization
~~~~~~~~~~~~~~~

List of algorithms
------------------

Error handlers
--------------

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
    # => 'eyJhbGciOiJIUzI1NiJ9.aGVsbG8.UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A'

Deserialization
~~~~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jws

    text = "eyJhbGciOiJIUzI1NiJ9.aGVsbG8.UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A"
    obj = jws.deserialize_compact(text, "secret")
    # => obj.payload == b"hello"

JSON Signature
--------------

The JWS JSON Serialization represents digitally signed or MACed
content as a JSON object.  This representation is neither optimized
for compactness nor URL-safe.

An example of a JSON serialization:

.. code-block:: json

    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures": [
        {
          "protected": "eyJhbGciOiJSUzI1NiJ9",
          "header": {"kid":"2010-12-29"},
          "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
        },
        {
          "protected": "eyJhbGciOiJFUzI1NiJ9",
          "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
          "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        }
      ]
    }

Serialization
~~~~~~~~~~~~~

.. code-block:: python

    import json
    from joserfc import jws
    from joserfc.jwk import KeySet

    members = [
        {
            "protected": {"alg": "RS256"},
            "header": {"kid": "2010-12-29"},
        },
        {
            "protected": {"alg": "ES256"},
            "header": {"kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"},
        },
    ]
    payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'

    with open("your-private-jwks.json") as f:
        data = json.load(f)
        # this key set SHOULD contains kid of "2010-12-29"
        # and "e9bc097a-ce51-4036-9562-d2ade882db0d"
        private_key_set = KeySet.import_key_set(data)

    value = jws.serialize_json(members, payload, private_key_set)
    #: this ``value`` is a dict which looks like the example above

Deserialization
~~~~~~~~~~~~~~~

.. code-block:: python

    with open("your-public-jwks.json") as f:
        data = json.load(f)
        # the public pair of your previous private key set
        public_key_set = KeySet.import_key_set(data)

    obj = jws.deserialize_json(value, public_key_set)
    # => assert obj.payload == payload

List of algorithms
------------------

``joserfc.jws`` module contains algorithms from RFC7518, RFC8037,
and RFC8812. Here lists all the algorithms:

Algorithm not allowed
~~~~~~~~~~~~~~~~~~~~~

When calling serialization and deserialization methods on ``joserfc.jws`` module
with non recommended algorithms, you may encounter the below error.

.. code-block:: python

    >>> from joserfc import jws
    >>> jws.serialize_compact({"alg": "HS384"}, b"payload", "secret")
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "$/joserfc/jws.py", line 99, in serialize_compact
        alg: JWSAlgModel = registry.get_alg(header["alg"])
      File "$/joserfc/rfc7515/registry.py", line 57, in get_alg
        raise ValueError(f'Algorithm of "{name}" is not allowed')
    ValueError: Algorithm of "HS384" is not allowed

``joserfc`` does support ``HS384``, but this algorithm is not recommended by
specifications, developers MUST explict specify the supported algorithms
either by the ``algorithms`` parameter, or ``registry`` parameter.

.. code-block:: python

    >>> from joserfc import jws
    >>> jws.serialize_compact({"alg": "HS384"}, b"payload", "secret", algorithms=["HS384"])
    'eyJhbGciOiJIUzM4NCJ9.cGF5bG9hZA.TJEvlp74g89hNRNGNZxCQvB7YDEAWP5vFAjgu1O9Qr5BLMj0NtvbxvYkVYPGp-xQ'

Developers can also apply the ``registry`` parameter to resolve this issue. Here is an example
of using :ref:`registry`.

.. code-block:: python

    >>> from joserfc import jws
    >>> registry = jws.JWSRegistry(algorithms=["HS384"])
    >>> jws.serialize_compact({"alg": "HS384"}, b"payload", "secret", registry=registry)
    'eyJhbGciOiJIUzM4NCJ9.cGF5bG9hZA.TJEvlp74g89hNRNGNZxCQvB7YDEAWP5vFAjgu1O9Qr5BLMj0NtvbxvYkVYPGp-xQ'

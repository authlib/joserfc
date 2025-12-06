:description: How to serialize and deserialize JWS in Compact, General JSON, and Flattened JSON Serialization.

.. _jws:

JSON Web Signature
==================

.. module:: joserfc
    :noindex:

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

An example of a compact serialization (line breaks for display purposes only):

.. code-block:: text

    eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
    dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

Serialization
~~~~~~~~~~~~~

You can call :meth:`jws.serialize_compact` to construct a compact JWS serialization:

.. code-block:: python

    from joserfc import jws
    from joserfc.jwk import OctKey

    key = OctKey.import_key("your-secret-key")
    protected = {"alg": "HS256"}
    jws.serialize_compact(protected, "hello", key)
    # => 'eyJhbGciOiJIUzI1NiJ9.aGVsbG8.i_RrfHeMxwHrhk5Xi3J_bU9B9O-gjkMaQtagtqiCndM'

A compact JWS is constructed by protected header, payload and a private key. In the above
example, ``protected`` is the "protected header" part, `"hello"` is the payload part, and
`"secret"` is a plain private key.

Deserialization
~~~~~~~~~~~~~~~

Calling :meth:`jws.deserialize_compact` to extract and verify the compact
serialization with a public key.

.. code-block:: python

    from joserfc import jws
    from joserfc.jwk import OctKey

    text = "eyJhbGciOiJIUzI1NiJ9.aGVsbG8.i_RrfHeMxwHrhk5Xi3J_bU9B9O-gjkMaQtagtqiCndM"
    key = OctKey.import_key("your-secret-key")
    obj = jws.deserialize_compact(text, key)
    # obj.protected => {"alg": "HS256"}
    # obj.payload => b"hello"

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

You can call :meth:`jws.serialize_json` to construct a JSON JWS serialization:

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

The JSON JWS serialization is constructed by members, payload and private key. A **member**
is a combination of protected header and public header:

.. code-block:: python

    member = {
        "protected": {"alg": "RS256"},
        "header": {"kid": "2010-12-29"},
    }

The ``protected`` header will be base64 encoded in the JSON serialization, together with
the payload to sign a signature for the member:

.. code-block:: none

    SIGNATURE INPUT =
        BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload)

    SIGNATURE =
        BASE64URL(SignMethod(SIGNATURE INPUT, Private Key))

In the above example, we passed a :class:`jwk.KeySet` as the private key parameter, the
:meth:`jws.serialize_json` will find the correct key in the key set by ``kid``.

Deserialization
~~~~~~~~~~~~~~~

Calling :meth:`jws.deserialize_json` to extract and verify the JSON
serialization with a public key.

.. code-block:: python

    with open("your-public-jwks.json") as f:
        data = json.load(f)
        # the public pair of your previous private key set
        public_key_set = KeySet.import_key_set(data)

    # value is the generated by above code
    obj = jws.deserialize_json(value, public_key_set)
    # => assert obj.payload == payload

General and Flattened
~~~~~~~~~~~~~~~~~~~~~

There are two types of JSON JWS serializations, "general" and "flattened".
The above example is a General JSON Serialization. A Flattened JSON Serialization
contains only one member. Compare the below examples:

.. code-block:: json
    :caption: Flattened JSON Serialization

    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected": "eyJhbGciOiJFUzI1NiJ9",
      "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    }

.. code-block:: json
    :caption: General JSON Serialization

    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures": [
        {
          "protected": "eyJhbGciOiJFUzI1NiJ9",
          "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
          "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        }
      ]
    }

You can pass a member dict to construct a flattened serialization; and
a list of members to construct a general serialization:

.. code-block:: python

    member = {
        "protected": {"alg": "ES256"},
        "header": {"kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"},
    }

    # flattened
    jws.serialize_json(member, payload, private_key)

    # general
    jws.serialize_json([member], payload, private_key)

The returned value from ``deserialize_json`` is an object of
:class:`jws.GeneralJSONSignature` or :class:`jws.FlattenedJSONSignature`,
you can tell if the signature is flattened or general with ``obj.flattened``:

.. code-block:: python

    obj = jws.deserialize_json(data, public_key)
    if obj.flattened:
        print("Flattened JSON Serialization")
    else:
        print("General JSON Serialization")

Algorithms
----------

``joserfc.jws`` module supports algorithms from RFC7518, RFC8037, RFC8812,
and RFC9864. Here lists all the algorithms ``joserfc.jws`` supporting:

============== ================================================ =========================
Algorithm name              Description                            Requirements
============== ================================================ =========================
none           No digital signature or MAC performed            :bdg-danger:`Deprecated`
HS256          HMAC using SHA-256                               :bdg-success:`Recommended`
HS384          HMAC using SHA-384                               :bdg-muted:`Optional`
HS512          HMAC using SHA-512                               :bdg-muted:`Optional`
RS256          RSASSA-PKCS1-v1_5 using SHA-256                  :bdg-success:`Recommended`
RS384          RSASSA-PKCS1-v1_5 using SHA-384                  :bdg-muted:`Optional`
RS512          RSASSA-PKCS1-v1_5 using SHA-512                  :bdg-muted:`Optional`
ES256          ECDSA using P-256 and SHA-256                    :bdg-success:`Recommended`
ES384          ECDSA using P-384 and SHA-384                    :bdg-muted:`Optional`
ES512          ECDSA using P-521 and SHA-512                    :bdg-muted:`Optional`
PS256          RSASSA-PSS using SHA-256 and MGF1 with SHA-256   :bdg-muted:`Optional`
PS384          RSASSA-PSS using SHA-384 and MGF1 with SHA-384   :bdg-muted:`Optional`
PS512          RSASSA-PSS using SHA-512 and MGF1 with SHA-512   :bdg-muted:`Optional`
EdDSA          Edwards-curve Digital Signature                  :bdg-danger:`Deprecated`
ES256K         ECDSA using secp256k1 curve and SHA-256          :bdg-muted:`Optional`
Ed25519        EdDSA using the Ed25519 parameter set            :bdg-muted:`Optional`
Ed448          EdDSA using the Ed448 parameter set              :bdg-muted:`Optional`
============== ================================================ =========================

.. versionadded:: 1.5.0

    ``Ed25519`` and ``Ed448`` are added since 1.5.0 per RFC9864.

The serialization and deserialization methods on ``joserfc.jws`` module accept
an ``algorithms`` parameter for specifying the allowed algorithms. By default,
those ``serialize`` and ``deserialize`` methods will ONLY allow recommended
algorithms defined by RFCs. With non recommended algorithms, you may encounter
an :ref:`UnsupportedAlgorithmError` error.

.. _unencoded_payload:

Unencoded Payload Option
------------------------

The unencoded payload option, defined in RFC7797, allows the payload of a
JWS (JSON Web Signature) to remain unencoded, without using base64 encoding.

To enable this option, you need to set the ``b64`` header parameter to ``false``
in the JWS header.

Here are examples demonstrating the usage of the ``b64`` option:

.. code-block:: python

    from joserfc.jws import serialize_compact, deserialize_compact
    from joserfc.jwk import OctKey

    key = OctKey.import_key("your-secret-key")
    protected = {"alg": "HS256", "b64": False, "crit": ["b64"]}
    value = serialize_compact(protected, "hello", key)
    # => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.hello.mdPbZLtc3tqQ6NCV1pKF-qfEx-3jtR6rv109phKAc4I'
    deserialize_compact(value, key)

.. note::

    The ``crit`` MUST be present with ``"b64"`` in its value set when
    ``b64`` is in the header.

Since the payload is not base64 encoded, if the payload contains non urlsafe
characters, the compact serialization will detach the payload:

.. code-block:: python

    from joserfc.jws import serialize_compact, deserialize_compact
    from joserfc.jwk import OctKey

    key = OctKey.import_key("your-secret-key")
    protected = {"alg": "HS256", "b64": False, "crit": ["b64"]}
    value = serialize_compact(protected, "$.02", key)
    # => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..6iWgAK_TZLgwzk1mhtxs6Imw-dJM1cRstsOKVQ5MjFQ'
    # since the payload is detached, you need to specify the
    # payload when calling deserialize_compact
    deserialize_compact(value, key, payload="$.02")

You can also use ``b64`` header for JSON serialization: ``serialize_json`` and
``deserialize_json``.

Guess Algorithms via Key
------------------------

If you are unsure which algorithm to use but already have a key, you can call the
:meth:`jws.JWSRegistry.guess_algorithm` method to determine a suitable algorithm:

.. code-block:: python

    from joserfc.jws import JWSRegistry, serialize_compact

    alg = JWSRegistry.guess_algorithm(key, JWSRegistry.Strategy.RECOMMENDED)
    protected = {"alg": alg.name}
    serialize_compact(protected, b"payload", key)

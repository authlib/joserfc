:description: How to encrypt and decrypt JWE in Compact, General JSON, and Flattened JSON Serialization.

.. _jwe:

JSON Web Encryption
===================

.. module:: joserfc
    :noindex:

JSON Web Encryption (JWE) represents encrypted content using
JSON-based data structures. (via RFC7516_)

.. _RFC7516: https://www.rfc-editor.org/rfc/rfc7516

Compact Encryption
------------------

The JWE Compact Serialization represents encrypted content as a
compact, URL-safe string.  This string is:

.. code-block:: none

    BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    BASE64URL(JWE Encrypted Key) || '.' ||
    BASE64URL(JWE Initialization Vector) || '.' ||
    BASE64URL(JWE Ciphertext) || '.' ||
    BASE64URL(JWE Authentication Tag)

An example of a compact serialization (line breaks for display purposes only):

.. code-block:: none

    eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
    OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
    ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
    Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
    mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
    1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
    6UklfCpIMfIjf7iGdXKHzg.
    48V1_ALb6US04U3b.
    5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
    SdiwkIr3ajwQzaBtQD_A.
    XFBoMYUZodetZdvTiFvSkQ

Encryption
~~~~~~~~~~

You can call :meth:`jwe.encrypt_compact` to construct a compact JWE serialization:

.. code-block:: python

    from joserfc import jwe
    from joserfc.jwk import OctKey

    protected = {"alg": "A128KW", "enc": "A128GCM"}
    key = OctKey.generate_key(128)  # algorithm requires key of big size 128
    data = jwe.encrypt_compact(protected, "hello", key)

A compact JWE is constructed by ``protected`` header, ``plaintext`` and a public key.
In the above example, ``protected`` is the "protected header" part, `"hello"` is the
plaintext part, and ``key`` is the public key part (oct key is a symmetric key, it is
a shared key, there is no public or private differences).

It is suggested that you learn the :ref:`jwk` section, and find the correct key type
according to :ref:`JSON Web Encryption Algorithms <jwe_algorithms>`.

Decryption
~~~~~~~~~~

It is very easy to decrypt the compact serialization in the previous example with
:meth:`jwe.decrypt_compact`:

.. code-block:: python

    obj = jwe.decrypt_compact(data, key)
    # obj.protected => {"alg": "A128KW", "enc": "A128GCM"}
    # obj.plaintext => b"hello"

.. note::

    If the algorithm is accepting an asymmetric key, you MUST use a private key
    in ``decrypt_compact`` method.

JSON Encryption
---------------

The JWE JSON Serialization represents encrypted content as a JSON
object.  This representation is neither optimized for compactness nor
URL safe.

An example of a JWE using the general JWE JSON Serialization is as follows:

.. code-block:: none

   {
      "protected":"<integrity-protected shared header contents>",
      "unprotected":<non-integrity-protected shared header contents>,
      "recipients":[
       {"header":<per-recipient unprotected header 1 contents>,
        "encrypted_key":"<encrypted key 1 contents>"},
       ...
       {"header":<per-recipient unprotected header N contents>,
        "encrypted_key":"<encrypted key N contents>"}],
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
   }

Encryption
~~~~~~~~~~

.. versionchanged:: 0.6.0

    ``jwe.JSONEncryption`` is separated to ``GeneralJSONEncryption`` and ``FlattenedJSONEncryption``.

The structure for JSON JWE serialization is a little complex, developers
SHOULD create an object of :class:`jwe.GeneralJSONEncryption` at first:

.. code-block:: python

    from joserfc.jwk import OctKey, RSAKey
    from joserfc.jwe import GeneralJSONEncryption, encrypt_json

    obj = GeneralJSONEncryption({"enc": "A128GCM"}, b"hello")

    # add first recipient with alg of A128KW
    key1 = OctKey.generate_key(128)
    obj.add_recipient({"alg": "A128KW"}, key1)

    # add second recipient with alg of RSA-OAEP
    key2 = RSAKey.generate_key()  # the alg requires RSAKey
    obj.add_recipient({"alg": "RSA-OAEP"}, key2)

    # since every recipient has recipient key,
    # there is no need to pass a public key parameter
    encrypt_json(obj, None)

If you prefer adding recipient keys from existing key set:

.. code-block:: python

    import json
    from joserfc.jwk import KeySet

    with open("your-jwks.json") as f:
        data = json.load(f)
        key_set = KeySet.import_key_set(data)

    # then add each recipient with ``kid``
    obj.add_recipient({"alg": "A128KW", "kid": "oct-key-id"})
    obj.add_recipient({"alg": "RSA-OAEP", "kid": "rsa-key-id"})
    # then pass the key set as the ``key`` parameter
    encrypt_json(obj, key_set)

Decryption
~~~~~~~~~~

Calling :meth:`jwe.decrypt_json` could decrypt the JSON Serialization in the above
example. Most of the time, you would need a JWK Set of private keys for decryption.

.. code-block:: python

    import json
    from joserfc import jwe
    from joserfc.jwk import KeySet

    with open("your-private-jwks.json") as f:
        data = json.load(f)
        key_set = KeySet.import_key_set(data)

    def parse_jwe(data):
        # this data is a dict of JWE JSON Serialization
        jwe.decrypt_json(data, key_set)

By default, ``jwe.decrypt_json`` will validate all the recipients, if one recipient
validation fails, the method will raise an error.

You can also change the default behavior to bypass the decryption with only one
recipient get verified:

.. code-block:: python

    registry = JWERegistry(verify_all_recipients=False)
    jwe.decrypt_json(data, key_set, registry=registry)

General and Flattened
~~~~~~~~~~~~~~~~~~~~~

The above example is a General JWE JSON Serialization, there is also a Flattened
JWE JSON Serialization. The Flattened one MUST ONLY contain one recipient.

The syntax of a JWE using the flattened JWE JSON Serialization is as follows:

.. code-block:: none

    {
      "protected":"<integrity-protected header contents>",
      "unprotected":<non-integrity-protected header contents>,
      "header":<more non-integrity-protected header contents>,
      "encrypted_key":"<encrypted key contents>",
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
    }

It is flattened, it moves all the members out of the ``recipients`` field. To
``encrypt_json`` into a flattened serialization, you can construct a
:class:`jwe.FlattenedJSONEncryption` instead:

.. code-block:: python

    obj = FlattenedJSONEncryption(protected, plaintext)

And make sure only adding one recipient.

Algorithms & Registry
---------------------

``joserfc.jwe`` module would ONLY allow recommended algorithms by default,
you can find which algorithm is recommended according to
:ref:`JSON Web Encryption Algorithms <jwe_algorithms>`.

It is possible to support non-recommended algorithms by passing the
``algorithms`` parameter, or with a custom ``registry``.

.. code-block:: python

    jwe.encrypt_compact(protected, plaintext, key, algorithms=["A128GCM", "A128KW"])

    registry = JWERegistry(algorithms=["A128GCM", "A128KW"])
    jwe.encrypt_compact(protected, plaintext, key, registry=registry)

The registry is a little complex, find out more on the :ref:`registry` section.

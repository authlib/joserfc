Migrating from PyJWT
====================

When migrating from PyJWT to ``joserfc``, there are a few key differences to be aware of.
``joserfc`` provides implementations for JWS (JSON Web Signature), JWE (JSON Web Encryption),
JWK (JSON Web Key), and JWT (JSON Web Token), whereas PyJWT focuses primarily on JWS and JWT.
Additionally, joserfc supports both JWT on JWS and JWT on JWE, offering more flexibility for
token handling.

jwt.encode
----------

Both PyJWT and joserfc use the ``.encode`` method to generate a JWT, but the parameter
structure differs between the two libraries.

.. code-block:: python
    :caption: PyJWT

    import jwt
    # jwt.encode(payload, key, algorithm)
    encoded_jwt = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")

.. code-block:: python
    :caption: joserfc

    from joserfc import jwt
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")  # use an explicit key
    # jwt.encode(header, payload, key)
    encoded_jwt = jwt.encode({"alg": "HS256"}, {"some": "payload"}, key)

jwt.decode
----------

Similarly, both PyJWT and joserfc use the ``.decode`` method to verify and decode a JWT,
but the parameter structure differs.

.. code-block:: python
    :caption: PyJWT

    token = jwt.decode(encoded_jwt, "secret", algorithms=["HS256"])
    # => {"some": "payload"}

.. code-block:: python
    :caption: joserfc

    from joserfc import jwt
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")
    token = jwt.decode(encoded_jwt, key)
    # => token.header : {"alg": "HS256"}
    # => token.claims : {"some": "payload"}

Non-plain string key
--------------------

When using a non-plain string key (equivalent to an "oct" key) in joserfc, such as
RSA, EC, or OKP keys, the library provides built-in implementations to handle these
key types. This eliminates the need for manual key handling, which is required in PyJWT.

Let's take an example using an RSA key:

.. code-block:: python
    :caption: PyJWT

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    private_pem = b"-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBS..."
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    encoded_jwt = jwt.encode({"some": "payload"}, private_key, algorithm="RS256")

.. code-block:: python
    :caption: joserfc

    from joserfc.jwk import RSAKey
    from joserfc import jwt

    private_pem = b"-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBS..."

    # Import the RSA key using joserfc's RSAKey
    key = RSAKey.import_key(private_pem)

    header = {'alg': 'RS256'}
    payload = {'some': 'payload'}
    encoded = jwt.encode(header, payload, key)

Claims validation
-----------------

Both PyJWT and ``joserfc`` provide mechanisms for claims validation, although
they differ in their approach.

In PyJWT, claims validation is performed within the ``.decode`` method itself. When decoding
a token, you can specify options such as ``verify_exp`` to validate the expiration time,
``verify_aud`` to validate the audience, and other options for additional claim validations.
Claims validation is an integral part of the decoding process.

On the other hand, ``joserfc`` follows a different approach by separating the decoding and
claims validation steps. The .decode method in joserfc is focused solely on decoding the
token and extracting the header and payload information. Claims validation is performed
separately using claims validators.

Verify "exp"
~~~~~~~~~~~~

.. code-block:: python
    :caption: PyJWT

    import jwt
    jwt.decode(encoded_jwt, options={"verify_exp": True})

.. code-block:: python
    :caption: joserfc

    from joserfc import jwt

    # claims requests has built-in validators for exp, nbf, iat
    claims_requests = jwt.JWTClaimsRegistry()
    token = jwt.decode(encoded_jwt, key)
    claims_requests.validate(token.claims)

Required claims
~~~~~~~~~~~~~~~

.. code-block:: python
    :caption: PyJWT

    import jwt
    jwt.decode(encoded_jwt, options={"require": ["exp", "iss", "sub"]})

.. code-block:: python
    :caption: joserfc

    from joserfc import jwt

    claims_requests = jwt.JWTClaimsRegistry(
        exp={"essential": True},
        iss={"essential": True},
        sub={"essential": True},
    )
    token = jwt.decode(encoded_jwt, key)
    claims_requests.validate(token.claims)

The ``JWTClaimsRegistry`` accepts each claim as an `Individual Claims Requests <ClaimsOption>`_
JSON object. You can learn more from :ref:`claims`.

.. _ClaimsOption: http://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests

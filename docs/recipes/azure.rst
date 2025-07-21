Dynamic keys for Azure
======================

In scenarios where you need to decode a JWT received from Azure (Microsoft), you
may encounter a situation where you are unaware of the public key required for the
decoding process until after the token arrives. In such cases, you will typically
need to retrieve the key set dynamically from the ``iss`` (issuer) value contained
within the JWT.

Let's illustrate this process using a JWT token extracted from Microsoft's official
documentation https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens:

.. code-block:: none

    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0ZaenhSY1ViMkMzbkVRN3N5SEpsWSJ9
    .eyJhdWQiOiI2ZTc0MTcyYi1iZTU2LTQ4NDMtOWZmNC1lNjZhMzliYjEyZTMiLCJpc3MiOiJodHRwczovL2x
    vZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3Y
    yLjAiLCJpYXQiOjE1MzcyMzEwNDgsIm5iZiI6MTUzNzIzMTA0OCwiZXhwIjoxNTM3MjM0OTQ4LCJhaW8iOiJ
    BWFFBaS84SUFBQUF0QWFaTG8zQ2hNaWY2S09udHRSQjdlQnE0L0RjY1F6amNKR3hQWXkvQzNqRGFOR3hYZDZ
    3TklJVkdSZ2hOUm53SjFsT2NBbk5aY2p2a295ckZ4Q3R0djMzMTQwUmlvT0ZKNGJDQ0dWdW9DYWcxdU9UVDI
    yMjIyZ0h3TFBZUS91Zjc5UVgrMEtJaWpkcm1wNjlSY3R6bVE9PSIsImF6cCI6IjZlNzQxNzJiLWJlNTYtNDg
    0My05ZmY0LWU2NmEzOWJiMTJlMyIsImF6cGFjciI6IjAiLCJuYW1lIjoiQWJlIExpbmNvbG4iLCJvaWQiOiI
    2OTAyMjJiZS1mZjFhLTRkNTYtYWJkMS03ZTRmN2QzOGU0NzQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhYmV
    saUBtaWNyb3NvZnQuY29tIiwicmgiOiJJIiwic2NwIjoiYWNjZXNzX2FzX3VzZXIiLCJzdWIiOiJIS1pwZmF
    IeVdhZGVPb3VZbGl0anJJLUtmZlRtMjIyWDVyclYzeERxZktRIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWF
    mLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiZnFpQnFYTFBqMGVRYTgyUy1JWUZBQSIsInZlciI6IjIuMCJ9
    .pj4N-w_3Us9DrBLfpCt

This token, obtained from Microsoft's official documentation, serves as an example for
decoding JWTs originating from Azure. The decoded payload might look like:

.. code-block:: json

    {
      "aud": "6e74172b-be56-4843-9ff4-e66a39bb12e3",
      "iss": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
      "iat": 1537231048,
      "nbf": 1537231048,
      "exp": 1537234948,
      "aio": "AXQAi/8IAAAAtAaZLo3ChMif6KOnttRB7eBq4/DccQzjcJGxPYy/C3jDa...",
      "azp": "6e74172b-be56-4843-9ff4-e66a39bb12e3",
      "azpacr": "0",
      "name": "Abe Lincoln",
      "oid": "690222be-ff1a-4d56-abd1-7e4f7d38e474",
      "preferred_username": "abeli@microsoft.com",
      "rh": "I",
      "scp": "access_as_user",
      "sub": "HKZpfaHyWadeOouYlitjrI-KffTm222X5rrV3xDqfKQ",
      "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",
      "uti": "fqiBqXLPj0eQa82S-IYFAA",
      "ver": "2.0"
    }

Steps for decoding
------------------

In order to decode JWT tokens from Azure, it is essential to retrieve the necessary
information from Microsoft's OpenID configuration, including the JSON Web Key Set (JWK Set)
URI. This information is crucial for verifying the tokens.

OpenID Configuration Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can obtain the OpenID configuration endpoint from Microsoft by forming a URL in
the following format:

.. code-block:: none

    https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration

In the example provided, replace ``{tenant}`` with your specific Azure tenant ID or
the tenant's globally unique identifier (GUID). The resulting URL will lead you
to the OpenID configuration details. Then, the OpenID configuration endpoint for
the above example could be:

.. code-block:: none

    https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0/.well-known/openid-configuration

JWK Set URI
~~~~~~~~~~~

Within the OpenID configuration details, you will find the JSON Web Key Set (JWK Set) URI.
This URI is used to access the keys required for verifying JWT tokens. The JWK Set URI
can typically be found within the configuration as follows:

.. code-block:: none

    https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys

Once again, remember to replace ``{tenant}`` with your Azure tenant ID or the appropriate identifier.
In the above example, the ``jwks_uri`` could be:

.. code-block:: none

    https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/discovery/v2.0/keys

Validating JWT Tokens
~~~~~~~~~~~~~~~~~~~~~

Once you have retrieved the JSON Web Key Set (JWK Set) from the JWK Set URI provided in the
OpenID configuration, you can proceed to validate JWT tokens.

Using a Callable Key
--------------------

In ``joserfc``, a callable key is a powerful feature that allows you to dynamically retrieve
and use the appropriate JSON Web Key (JWK) for token decoding. In the context of Azure tokens,
you can implement a callable key to fetch the JWKs from the JWK Set URI and select the correct
key based on the kid (Key ID) in the token's header.

.. code-block:: python

    import json
    import requests
    from joserfc.jws import CompactSignature
    from joserfc.jwk import KeySet
    from joserfc import jwt

    def load_key(obj: CompactSignature):
        claims = json.loads(obj.payload)
        issuer_url = claims['iss']

        # retrieve OpenID Configuration Endpoint
        openid_configuration_endpoint = f'{issuer_url}/.well-known/openid-configuration'
        resp = requests.get(openid_configuration_endpoint)

        # retrieve JWK Set URI
        jwks_uri = resp.json()['jwks_uri']
        resp = requests.get(jwks_uri)
        key_set = KeySet.import_key_set(resp.json())
        return key_set

    # pass load_key as a callable key to `jwt.decode` method
    jwt.decode(token_string, load_key)

When using the callable key method in ``joserfc`` to decode the tokens, it retrieves
the key dynamically on each token decoding request. However, you may encounter performance
issues due to the repeated retrieval of keys. In such cases, it's advisable to optimize
the callable key by implementing key set caching based on the issuer.

Let's enhance the callable key method to improve its efficiency.

.. code-block:: python

    import functools

    @functools.cache
    def fetch_key_set(issuer: str):
        openid_configuration_endpoint = f'{issuer}/.well-known/openid-configuration'
        resp = requests.get(openid_configuration_endpoint)
        jwks_uri = resp.json()['jwks_uri']
        resp = requests.get(jwks_uri)
        return KeySet.import_key_set(resp.json())

    def load_key(obj: CompactSignature):
        claims = json.loads(obj.payload)
        key_set = fetch_key_set(claims['iss'])
        return key_set

In this enhanced callable key, an LRU (Least Recently Used) cache is used to store
JWK Sets for different issuers. When decoding a token, the callable key function first
checks if the JWK Set for the specific issuer is available in the cache. If it's not,
it fetches the JWK Set for the issuer, caches it, and then selects the appropriate JWK
based on the kid. This caching mechanism significantly reduces the network requests for
JWK Sets and improves the efficiency of token decoding.

Manual Token Decoding
---------------------

If you prefer a more hands-on approach and want to decode the token step by step,
you can opt for a manual decoding process. This method allows you to extract the
token string and work with it directly. Since the token is a JWT in JWS format,
you can utilize the ``extract_compact`` method from the JWS module to obtain the
necessary information. The result of this extraction is an object of type
:class:`~joserfc.jws.CompactSignature`.

.. code-block:: python

    from joserfc.jws import extract_compact, CompactSignature

    obj: CompactSignature = extract_compact(token_string)

Similar to the approach detailed in the "Using a Callable Key" section, you can
retrieve the key set based on the issuer (``iss``) claim. This method allows you to
access the necessary keys for token verification.

.. code-block:: python

    @functools.cache
    def fetch_key_set(issuer: str):
        openid_configuration_endpoint = f'{issuer}/.well-known/openid-configuration'
        resp = requests.get(openid_configuration_endpoint)
        jwks_uri = resp.json()['jwks_uri']
        resp = requests.get(jwks_uri)
        return KeySet.import_key_set(resp.json())

    claims = json.loads(obj.payload)
    key_set = fetch_key_set(claims['iss'])

Once you have obtained the key set based on the issuer (``iss``) claim, you can use this
set of keys to decode the token.

.. code-block:: python

    from joserfc import jwt

    token = jwt.decode(token_string, key_set)

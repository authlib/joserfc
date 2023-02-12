Generating keys
===============


Generating EC keys
------------------

EC key with crv P-256
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jwk

    key = jwk.generate_key('EC', 'P-256', private=True)
    private_pem = key.as_bytes(private=True)
    public_pem = key.as_bytes(private=True)

Using OpenSSL command line tool:

.. code-block:: shell

    # generate private key
    openssl ecparam -name prime256v1 -genkey -noout -out ec-p256-private.pem

    # extract public key
    openssl ec -in ec-p256-private.pem -pubout -out ec-p256-public.pem

.. hint:: OpenSSL encourage using prime256v1 instead of secp256r1


EC key with crv P-384
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jwk

    key = jwk.generate_key('EC', 'P-384', private=True)
    private_pem = key.as_bytes(private=True)
    public_pem = key.as_bytes(private=True)

.. code-block:: shell

    # generate private key
    openssl ecparam -name secp384r1 -genkey -noout -out ec-p384-private.pem

    # extract public key
    openssl ec -in ec-p384-private.pem -pubout -out ec-p384-public.pem


EC key with crv P-512
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from joserfc import jwk

    key = jwk.generate_key('EC', 'P-512', private=True)
    private_pem = key.as_bytes(private=True)
    public_pem = key.as_bytes(private=True)

.. code-block:: shell

    # generate private key
    openssl ecparam -name secp521r1 -genkey -noout -out ec-p512-private.pem

    # extract public key
    openssl ec -in ec-p512-private.pem -pubout -out ec-p512-public.pem

.. note:: It is **secp521r1**, not secp512r1. But the "crv" value in EC Key is "P-512".

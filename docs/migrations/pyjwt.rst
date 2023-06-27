Migrating from PyJWT
====================

Compare the code from PyJWT:

.. code-block:: python
    :caption: PyJWT

    import jwt
    encoded_jwt = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")

And ``joserfc``:

.. code-block:: python
    :caption: joserfc

    from joserfc import jwt
    encoded_jwt = jwt.encode({"alg": "HS256"}, {"some": "payload"}, "secret")

:description: Advanced usage of registry for JWS, and JWE.

.. _registry:

Registry
========

.. module:: joserfc
    :noindex:

The ``registry`` is specifically designed to store supported algorithms,
allowed algorithms, registered header parameters, and provides methods
to validate algorithms and headers.

Why registry
------------

Algorithms
----------

The ``JWSRegistry`` or ``JWERegistry`` serves as a storage for all supported
algorithms in JWS or JWE. By default, it enforces the usage of recommended
algorithms, ensuring a higher level of security.

Find all the supported and recommended algorithms in:

- :ref:`jws_algorithms`
- :ref:`jwe_algorithms`

You have the flexibility to create a custom registry tailored to your specific
program requirements, allowing you to define and restrict the algorithms used.
For instance, you can design a custom JWS registry that only permits the usage
of ``RS256`` and ``ES256`` algorithms. This ensures that only these specific
algorithms are allowed in your program.

.. code-block:: python

    from joserfc.jws import JWSRegistry

    registry = JWSRegistry(algorithms=["RS256", "ES256"])
    # jws.serialize_compact(protected, payload, key, registry=registry)

An example of a custom JWE registry that only permits the usage of
``{"alg": "A128KW", "enc": "A128GCM"}``:

.. code-block:: python

    from joserfc.jwe import JWERegistry

    registry = JWERegistry(algorithms=["A128KW", "A128GCM"])
    # jwe.encrypt_compact(protected, payload, key, registry=registry)

Headers
-------

By default, the ``JWSRegistry`` only permits the usage of registered header
parameters. Additionally, it verifies the validity of the header parameter
values before allowing their usage.

Type checking
~~~~~~~~~~~~~

.. code-block:: python

    >>> from joserfc import jws
    >>> jws.serialize_compact({"alg": "HS256", "kid": 123}, "hello", "secret")
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "$/joserfc/jws.py", line 98, in serialize_compact
        registry.check_header(protected)
      File "$/joserfc/rfc7515/registry.py", line 63, in check_header
        check_registry_header(self.header_registry, header)
      File "$/joserfc/registry.py", line 187, in check_registry_header
        raise ValueError(f'"{key}" in header {error}')
    ValueError: "kid" in header must be a str

In the above example, ``kid`` MUST be a string instead of an integer. The default
registry validates the ``kid`` before processing the serialization.

Critical headers
~~~~~~~~~~~~~~~~

Additional headers
~~~~~~~~~~~~~~~~~~

Registry for JWT
----------------

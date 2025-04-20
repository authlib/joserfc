:description: Advanced usage of registry for JWS, and JWE.

.. _registry:

Registry
========

.. module:: joserfc
    :noindex:

The ``registry`` is specifically designed to store supported algorithms,
allowed algorithms, registered header parameters, and provides methods
to validate algorithms and headers.

.. note::

    We'll use ``JWSRegistry`` as our reference, but keep in mind that
    the behavior of ``JWERegistry`` is identical.

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

The header parameter registry for JWS and JWE performs an initial check on
the value type.

.. code-block:: python

    >>> from joserfc import jws
    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("secret")
    >>> jws.serialize_compact({"alg": "HS256", "kid": 123}, "hello", key)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File ".../joserfc/jws.py", line 111, in serialize_compact
        registry.check_header(protected)
      File ".../joserfc/rfc7515/registry.py", line 68, in check_header
        validate_registry_header(self.header_registry, header)
      File ".../joserfc/registry.py", line 194, in validate_registry_header
        raise InvalidHeaderValueError(f"'{key}' in header {error}")
    joserfc.errors.InvalidHeaderValueError: invalid_header_value: 'kid' in header must be a str

In the above example, ``kid`` MUST be a string instead of an integer. The default
registry validates the ``kid`` before processing the serialization.

Critical headers
~~~~~~~~~~~~~~~~

There is a special "crit" header parameter for JWS and JWE, which specifies
the critical header parameters. These critical parameters are considered mandatory,
indicating that they must be present. For example:

.. code-block:: python

    >>> from joserfc import jws
    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("secret")
    >>> jws.serialize_compact({"alg": "HS256", "crit": ["kid"]}, "hello", key)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File ".../joserfc/jws.py", line 111, in serialize_compact
        registry.check_header(protected)
      File ".../joserfc/rfc7515/registry.py", line 67, in check_header
        check_crit_header(header)
      File ".../joserfc/registry.py", line 202, in check_crit_header
        raise MissingCritHeaderError(k)
    joserfc.errors.MissingCritHeaderError: missing_crit_header: Missing critical 'kid' value in header

Since "kid" is listed as a critical (``crit``) header parameter, it is mandatory
and must be included in the header.

Additional headers
~~~~~~~~~~~~~~~~~~

By default, the registry for JWS and JWE only permits registered header parameters.
Any additional header beyond those supported by the algorithm will result in an error.

.. code-block:: python

    >>> from joserfc import jws
    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.import_key("secret")
    >>> jws.serialize_compact({"alg": "HS256", "custom": "hi"}, "hello", key)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File ".../joserfc/jws.py", line 111, in serialize_compact
        registry.check_header(protected)
      File ".../joserfc/rfc7515/registry.py", line 70, in check_header
        check_supported_header(self.header_registry, header)
      File ".../joserfc/registry.py", line 183, in check_supported_header
        raise UnsupportedHeaderError(f"Unsupported {unsupported_keys} in header")
    joserfc.errors.UnsupportedHeaderError: unsupported_header: Unsupported {'custom'} in header

To resolve this error, you have two options. First, you can register the
additional header parameters with the registry. This allows the registry
to recognize and validate those parameters instead of raising an error.

.. code-block:: python

    from joserfc import jws
    from joserfc.jws import JWSRegistry
    from joserfc.registry import HeaderParameter
    from joserfc.jwk import OctKey

    key = OctKey.import_key("secret")

    additional_header_registry = {
        "custom": HeaderParameter("Custom message", "str", required=True),
    }
    registry = JWSRegistry(additional_header_registry)

    # it will not raise any error
    jws.serialize_compact({"alg": "HS256", "custom": "hi"}, "hello", key, registry=registry)

    # this will raise an error, because we "custom" is defined to be required
    jws.serialize_compact({"alg": "HS256"}, "hello", key, registry=registry)

Alternatively, you can choose to disable the strict header checking altogether.
By turning off strict header checking, the registry will no longer raise an
error for unrecognized header parameters. However, please note that this approach
may compromise the security and integrity of the token, so it should be used with caution.

.. code-block:: python

    registry = JWSRegistry(strict_check_header=False)
    # will not raise any error
    jws.serialize_compact({"alg": "HS256", "custom": "hi"}, "hello", key, registry=registry)

Registry for JWT
----------------

JSON Web Token (JWT) is built on top of :ref:`jws` or :ref:`jwe`. The ``encode`` and ``decode``
methods accept a ``registry`` parameter. Depending on the algorithm of the JWT, you need to
decide whether to use ``JWSRegistry`` or ``JWERegistry``.

Errors & Warnings
=================

Here are some common errors and warnings, and how to handle them.

SecurityWarning
---------------

.. versionadded:: 1.2.0

You may encounter a ``SecurityWarning`` when using potentially
unsafe algorithms or generating insecure keys. These warnings
do not interrupt the execution of your application — they are
simply printed to standard output (e.g., your terminal).

If you prefer to suppress these warnings, you can use Python’s
built-in ``warnings`` module:

.. code-block:: python

    import warnings
    from joserfc.errors import SecurityWarning

    warnings.simplefilter('ignore', SecurityWarning)

With this configuration, ``SecurityWarning`` messages will no
longer appear. Be cautious when suppressing these warnings, as
they are meant to alert you to potentially insecure practices.

UnsupportedAlgorithmError
-------------------------

.. versionadded:: 1.1.0

By default, **ONLY recommended** :ref:`jwa` are allowed. With non recommended
algorithms, you may encounter the ``UnsupportedAlgorithmError`` error.

.. code-block:: python

    >>> from joserfc import jws
    >>> from joserfc.jwk import OctKey
    >>> key = OctKey.generate_key()
    >>> jws.serialize_compact({"alg": "HS384"}, b"payload", key)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File ".../joserfc/jws.py", line 112, in serialize_compact
        alg: JWSAlgModel = registry.get_alg(protected["alg"])
                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      File ".../joserfc/_rfc7515/registry.py", line 60, in get_alg
        raise UnsupportedAlgorithmError(f'Algorithm of "{name}" is not recommended')
    joserfc.errors.UnsupportedAlgorithmError: unsupported_algorithm: Algorithm of "HS384" is not recommended

Because "HS384" is not a recommended algorithm, it is not allowed by default. You
SHOULD enable it manually by passing an ``algorithms`` parameter:

.. code-block:: python

    >>> jws.serialize_compact({"alg": "HS384"}, b"payload", key, algorithms=["HS384"])

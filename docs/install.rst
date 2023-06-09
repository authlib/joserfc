:description: Get started with joserfc from installation.

Installation
============

We recommend using the latest version of Python. ``joserfc`` supports Python 3.8 and newer.
The package has a dependency of cryptography_, if you encountered any issues related with
cryptography, you can follow the documentation
`installation of cryptography <https://cryptography.io/en/latest/installation/>`_.

.. _cryptography: https://cryptography.io/

pip install
-----------

``joserfc`` is conveniently available as a Python package on PyPI and can be easily
installed using pip.

.. code-block:: shell

    pip install joserfc

pyproject.toml
--------------

If you're using ``pyproject.toml`` for your Python project, you can add ``joserfc``
to ``project.dependencies``.

.. code-block:: ini
    :caption: pyproject.toml

    [project]
    dependencies = [
        "joserfc",
    ]

Pipfile
-------

If you prefer **pipenv**, you would like to track dependencies in ``Pipfile``, then
add ``joserfc`` to ``[packages]`` section.

.. code-block:: ini
    :caption: Pipfile

    [packages]
    joserfc = "*"

requirements.txt
----------------

If you're tracking dependencies in ``requirements.txt``, you can add ``joserfc`` to
the requirements file.

.. code-block:: text
    :caption: requirements.txt

    joserfc

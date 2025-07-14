:description: Get started with joserfc from installation.

Installation
============

.. rst-class:: lead

    Get started with **joserfc** from installation.

----

We recommend using the latest version of Python. ``joserfc`` supports Python 3.8 and newer.
The package has a dependency of cryptography_, if you encountered any issues related with
cryptography, you can follow the documentation
`installation of cryptography <https://cryptography.io/en/latest/installation/>`_.

.. _cryptography: https://cryptography.io/

pip install
-----------

``joserfc`` is conveniently available as a Python package on PyPI and can be easily
installed using pip.

.. tab-set::

    .. tab-item:: pip

        .. code-block:: shell

            pip install joserfc

    .. tab-item:: uv

        .. code-block:: shell

            uv add joserfc

.. important::

    To use :ref:`chacha20` algorithms, developers have to install the ``PyCryptodome`` module.

    .. code-block:: shell

        pip install joserfc pycryptodome

conda install
-------------

``joserfc`` is also available from conda-forge_:

.. code-block:: shell

    conda install conda-forge::joserfc

.. _conda-forge: https://anaconda.org/conda-forge/joserfc

Dependency management
---------------------

There are several ways to manage the dependencies of your project, here are some examples
to track ``joserfc`` in your project.

pyproject.toml
~~~~~~~~~~~~~~

If you're using ``pyproject.toml`` for your Python project, you can add ``joserfc``
to ``project.dependencies``.

.. code-block:: ini
    :caption: pyproject.toml

    [project]
    dependencies = [
        "joserfc",
    ]

requirements.txt
~~~~~~~~~~~~~~~~

If you're tracking dependencies in ``requirements.txt``, you can add ``joserfc`` to
the requirements file.

.. code-block:: text
    :caption: requirements.txt

    joserfc

Contributing
============

Contributions are welcome, and they are greatly appreciated!

Types of contributions
----------------------

There are many ways you can contribute.

Report bugs
~~~~~~~~~~~

You're welcome to report bugs at
`GitHub Issues <https://github.com/authlib/joserfc/issues>`_.

Before reporting a bug, please verify your bug against the latest
code in ``main`` branch.

When reporting a bug, please including:

- Your operating system name and version.
- Your Python version.
- Details to reproduce the bug.

Submit fixes
~~~~~~~~~~~~

Once you found a bug that you can fix, you're welcome
to submit your pull request.

Please follow our `git commit conventions <https://www.conventionalcommits.org/en/v1.0.0/>`_.

Improve documentation
~~~~~~~~~~~~~~~~~~~~~

Everyone wants a good documentation. There may be mistakes
or things missing in the documentation, you're welcome to
help us improving the documentation.

.. _development:

Development
-----------

Once you cloned ``joserfc``'s source code, you can setup a development
environment to work on.

Install
~~~~~~~

Install `uv <https://docs.astral.sh/uv/getting-started/installation/>`_ and use
Python 3.11 or newer. Create the development environment from the committed
``uv.lock`` file:

.. code-block:: shell

    uv sync --locked

``uv`` creates and manages ``.venv`` automatically. Dependency groups are defined
in ``pyproject.toml``; the ``dev`` group is installed by default. Install the
documentation dependencies with:

.. code-block:: shell

    uv sync --locked --group docs

When changing dependencies in ``pyproject.toml``, update and commit ``uv.lock``:

.. code-block:: shell

    uv lock

Use ``uv lock --upgrade-package <name>`` to update a specific dependency.

Run tests
~~~~~~~~~~

Once you made some code changes, you can add your test
case in the ``tests`` folder, then verify it with:

.. code-block:: shell

    uv run --locked pytest
    uv run --locked ruff check
    uv run --locked mypy

Build documentation
~~~~~~~~~~~~~~~~~~~

.. code-block:: shell

    uv run --locked --group docs make build-docs -e lang=en

Next
----

.. toctree::
    structure
    translation
    authors
    sponsors

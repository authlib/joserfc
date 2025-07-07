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

venv
~~~~

I strongly suggest you create a virtual environment with ``venv``:

.. code-block:: shell

    python -m venv .venv
    source .venv/bin/active

Install
~~~~~~~

Then install the Python requirements for development:

.. code-block:: shell

    pip install -r requirements-dev.txt

Run tests
~~~~~~~~~~

Once you made some code changes, you can add your test
case in the ``tests`` folder, then verify it with:

.. code-block:: shell

    pytest

Next
----

.. toctree::
    structure
    translation
    authors
    sponsors

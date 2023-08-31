:description: Help us translating this documentation into other languages.

Translations
============

To begin translating this documentation into other languages, please
start by referring to the :ref:`development` guide, which will help
you set up a suitable development environment. Afterward, navigate to
the docs folder using the following command:

.. code-block:: shell

    cd docs

Generate .pot files
-------------------

Before creating translations in your desired languages, you need to
generate the source ``.pot`` files. This can be accomplished using
the following command:

.. code-block:: shell

    sphinx-build -b gettext . _build/gettext

Update languages
----------------

Next, proceed to generate the ``.po`` files in your preferred
languages using the ``sphinx-intl`` tool:

.. code-block:: shell

    sphinx-intl update -p _build/gettext -l de

In this example, we're using the language code ``de`` to represent German.

Writing the Translations
------------------------

Following the previous command, the ``.po`` files will be generated within
the ``locales/de/LC_MESSAGES`` directory. You can now edit these files to
add the German translations accordingly.

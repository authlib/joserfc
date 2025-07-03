API stability
=============

The API of joserfc is currently a work in progress and may not be considered
fully stable. However, with each release, the API stability is improving and
getting closer to a stable state.

Interfaces
----------

``joserfc`` have released **1.0.0**, the method names and their parameters
in modules ``joserfc.jws``, ``joserfc.jwe``, ``joserfc.jwk`` and ``joserfc.jwt``
are expected to remain stable. This means that once you have updated your code
to use the methods provided by joserfc, you can rely on them without the need
for frequent changes.

Python Versions
---------------

``joserfc`` is designed to support Python 3.8 and above. It is recommended to use
``joserfc`` with Python versions 3.8 and higher to ensure compatibility and take
advantage of the latest language features and improvements.

New RFCs
---------

To maintain a stable and reliable library, joserfc will not introduce new RFC
implementations until the 1.0.0 release. This approach ensures that the existing
functionality is thoroughly tested and the library reaches a mature state before
incorporating new specifications.

When new RFC implementations are added after the 1.0.0 release, the minor version
of joserfc will be incremented. This versioning approach helps to communicate the
introduction of new features and RFC support to users, while also indicating
potential changes to the API and behavior.

Upgrade notes
-------------

Please note that while efforts are made to maintain compatibility and stability,
it is always a good practice to thoroughly test and validate your code when upgrading
to a new version of joserfc to ensure a smooth transition and avoid any potential
compatibility issues.

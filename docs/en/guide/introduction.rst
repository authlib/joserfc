:description: Introduction of joserfc, and why it is created.

Introduction
============

``joserfc`` is a Python library that provides a comprehensive implementation
of several essential JSON Object Signing and Encryption (JOSE) standards.

Derived from Authlib_, ``joserfc`` offers a redesigned API specifically tailored
to JOSE functionality, making it easier for developers to work with JWS, JWE, JWK,
JWA, and JWT in their Python applications.

.. _Authlib: https://authlib.org/

Features
--------

- **Python Type Hints**: ``joserfc`` takes advantage of Python's type hinting
  capabilities, providing a more expressive and readable codebase. The use of
  type hints enhances development workflows by enabling better static analysis,
  improved IDE support, and more reliable code refactoring.
  
- **Organized Codebase with RFC Compliance**: ``joserfc`` is structured following
  the RFC standards, ensuring clear separation and organization of the different
  JOSE functionalities. It strictly follows the latest versions of the JOSE standards,
  guaranteeing the highest level of interoperability and compliance.

Why joserfc?
------------

``joserfc`` is derived from Authlib to facilitate easy maintenance and modularity.
Previously, Authlib was developed as a mono library to design a comprehensive API
that covered a wide range of authentication and security needs. However, as the
project evolved, it became evident that splitting the modules from Authlib would
improve maintainability and provide more focused and specialized libraries.

With ``joserfc``, developers can now benefit from a standalone library dedicated
specifically to JOSE standards. This focused approach allows for better code
organization, improved documentation, and a more streamlined development experience.
By utilizing ``joserfc``, developers can confidently integrate JOSE functionalities
into their projects, knowing that they are working with a dedicated and well-maintained
solution.

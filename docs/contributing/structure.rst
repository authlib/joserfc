Code structure
==============

The code structure of ``joserfc`` follows an organized approach based on RFC specifications.
It is designed to enhance understanding by grouping the code according to specific RFCs.

Overview
--------

The overall structure is organized as follows:

.. code-block:: none

    joserfc/
      _rfc7515/          # Code related to RFC7515 (JWS)
      _rfc7516/          # Code related to RFC7516 (JWE)
      _rfc7517/          # Code related to RFC7517 (JWK)
      _rfc7518/          # Code related to RFC7518 (JWA)
      _rfc7519/          # Code related to RFC7519 (JWT)
      _rfc7638/          # Code related to RFC7638 (JWK Thumbprint)
      _rfc7797/          # Code related to RFC7797 (Unencoded Payload Option)
      _rfc8037/          # Code related to RFC8037 (OKP Keys)
      _rfc8812/          # Code related to RFC8812 (secp256k1 Curve)
      jws.py             # High-level API for JWS operations
      jwe.py             # High-level API for JWE operations
      jwk.py             # High-level API for JWK operations
      jwt.py             # High-level API for JWT operations

This structure allows developers to easily navigate and comprehend each RFC specification
individually. The code is organized from low-level to high-level, making it intuitive and
convenient to understand and use. Developers can utilize the higher-level APIs
(``jws.py``, ``jwe.py``, ``jwk.py``, ``jwt.py``) without needing to delve into the
lower-level implementation details.

By following this structured approach, joserfc ensures clarity, ease of understanding,
and simplicity in both comprehension and utilization of the library.

New RFCs
--------

To add a new RFC implementation to ``joserfc``, you can follow a straightforward approach:

1. Create a new folder within the ``joserfc`` package, named after the RFC number.
2. Place the relevant code files and modules related to the new RFC within the created folder.
3. Organize the code structure within the folder to align with the RFC's specifications and guidelines.
4. Update the necessary high-level APIs (``jws.py``, ``jwe.py``, ``jwk.py``, ``jwt.py``) to integrate
   and expose the new RFC implementation.

By adhering to this approach, you can easily incorporate new RFC implementations into ``joserfc``,
maintaining a well-organized and extensible codebase.

Draft RFCs
----------

Draft RFCs are specifications that are still in the draft phase and subject to potential changes.
In ``joserfc``, draft implementations are placed within the ``joserfc.drafts`` package. It's important
to note that draft implementations are not typically accepted as part of the main ``joserfc`` library
until the RFC is officially published and stabilized.

Although draft implementations are included within the ``joserfc.drafts`` package for exploration
and experimentation purposes, they may not fully adhere to the final version of the RFC. It is
recommended to use caution when relying on draft implementations, as they may undergo significant
changes or be incompatible with the final RFC specification.

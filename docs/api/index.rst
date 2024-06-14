API References
==============

Here covers the interfaces of JWS, JWE, JWK, and JWT.

.. grid:: 2
    :gutter: 2
    :padding: 0

    .. grid-item-card:: JWS API
        :link-type: ref
        :link: jws_api

        Most :ref:`jwt` are encoded with JWS in compact serialization.

    .. grid-item-card:: JWE API
        :link-type: ref
        :link: jwe_api

        JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.

    .. grid-item-card:: JWK API
        :link-type: ref
        :link: jwk_api

        Learn how to use ``OctKey``, ``RSAKey``, ``ECKey``, ``OKPKey``, and JSON Web Key Set.

    .. grid-item-card:: JWT API
        :link-type: ref
        :link: jwt_api

        JSON Web Token (JWT) is built on top of :ref:`jws` or :ref:`jwe`.

.. toctree::
    :hidden:

    jws
    jwe
    jwk
    jwt
    errors

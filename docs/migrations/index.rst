Migrations
==========

Here are some migration guides to help you transition from other libraries
to ``joserfc``:

.. toctree::

   authlib
   pyjwt
   python-jose


Comparison
----------

joserfc is the most feature-complete Python library for the JOSE specifications,
providing full coverage of all relevant RFCs.

The following highlights the key differences between joserfc and other Python libraries:

==============  ====================  ====================  ====================  ====================  ====================
 Comparison         joserfc             authlib.jose          pyjwt                 python-jose           jwcrypto
==============  ====================  ====================  ====================  ====================  ====================
 Type Hints      :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-danger:`No`
 Compact JWS     :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`
 JSON JWS        :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-danger:`No`      :bdg-success:`Yes`
 Compact JWE     :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-success:`Yes`    :bdg-success:`Yes`
 JSON JWE        :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-danger:`No`      :bdg-success:`Yes`
 JWK             :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`
 JWT             :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`
 RFC7638         :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-danger:`No`      :bdg-success:`Yes`
 RFC7797         :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-success:`Yes`
 RFC8037         :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-success:`Yes`
 RFC8812         :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-success:`Yes`
 RFC9278         :bdg-success:`Yes`    :bdg-danger:`No`      :bdg-danger:`No`      :bdg-danger:`No`      :bdg-danger:`No`
==============  ====================  ====================  ====================  ====================  ====================

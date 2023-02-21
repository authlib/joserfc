from abc import ABCMeta, abstractmethod


class JWSAlgModel(object, metaclass=ABCMeta):
    """Interface for JWS algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWS with this base implementation.
    """
    name: str
    description: str
    recommended: bool = False
    algorithm_type = 'JWS'
    algorithm_location = 'sig'

    def __str__(self):
        return self.name

    @abstractmethod
    def sign(self, msg: bytes, key) -> bytes:
        """Sign the text msg with a private/sign key.

        :param msg: message bytes to be signed
        :param key: private key to sign the message
        :return: bytes
        """
        pass

    @abstractmethod
    def verify(self, msg: bytes, sig: bytes, key) -> bool:
        """Verify the signature of text msg with a public/verify key.

        :param msg: message bytes to be signed
        :param sig: result signature to be compared
        :param key: public key to verify the signature
        :return: boolean
        """
        pass

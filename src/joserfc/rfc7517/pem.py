from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_ssh_public_key,
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption,
)
from cryptography.hazmat.backends import default_backend


def load_pem_key(raw: bytes, ssh_type=None, key_type=None, password=None):
    if ssh_type and raw.startswith(ssh_type):
        return load_ssh_public_key(raw, backend=default_backend())

    if key_type == 'public':
        return load_pem_public_key(raw, backend=default_backend())

    if key_type == 'private' or password is not None:
        return load_pem_private_key(raw, password=password, backend=default_backend())

    if b'PUBLIC' in raw:
        return load_pem_public_key(raw, backend=default_backend())

    if b'PRIVATE' in raw:
        return load_pem_private_key(raw, password=password, backend=default_backend())

    if b'CERTIFICATE' in raw:
        cert = load_pem_x509_certificate(raw, default_backend())
        return cert.public_key()

    try:
        return load_pem_private_key(raw, password=password, backend=default_backend())
    except ValueError:
        return load_pem_public_key(raw, backend=default_backend())


def dump_pem_key(key, encoding=None, private=False, password=None) -> str:
    """Export key into PEM/DER format bytes.

    :param encoding: "PEM" or "DER"
    :param private: export private key or public key
    :param password: encrypt private key with password
    :return: bytes
    """

    if encoding is None or encoding == 'PEM':
        encoding = Encoding.PEM
    elif encoding == 'DER':
        encoding = Encoding.DER
    else:
        raise ValueError('Invalid encoding: {!r}'.format(encoding))

    if private:
        if password is None:
            encryption_algorithm = NoEncryption()
        else:
            encryption_algorithm = BestAvailableEncryption(to_bytes(password))
        return key.private_bytes(
            encoding=encoding,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
    return key.public_bytes(
        encoding=encoding,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

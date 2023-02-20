import base64
import string
import struct
import json
import random


def to_bytes(x, charset='utf-8', errors='strict'):
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode(charset, errors)
    if isinstance(x, (int, float)):
        return str(x).encode(charset, errors)
    return bytes(x)


def json_dumps(data: dict, ensure_ascii=False):
    return json.dumps(data, ensure_ascii=ensure_ascii, separators=(',', ':'))


def urlsafe_b64decode(s: bytes) -> bytes:
    s += b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def urlsafe_b64encode(s: bytes) -> bytes:
    return base64.urlsafe_b64encode(s).rstrip(b'=')


def base64_to_int(s: str) -> int:
    data = urlsafe_b64decode(to_bytes(s))
    buf = struct.unpack('%sB' % len(data), data)
    return int(''.join(["%02x" % byte for byte in buf]), 16)


def int_to_base64(num: int) -> str:
    if num < 0:
        raise ValueError('Must be a positive integer')

    s = num.to_bytes((num.bit_length() + 7) // 8, 'big', signed=False)
    return urlsafe_b64encode(s).decode('utf-8', 'strict')


def json_b64encode(text, charset='utf-8') -> bytes:
    if isinstance(text, dict):
        text = json_dumps(text)
    return urlsafe_b64encode(to_bytes(text, charset))


def json_b64decode(text, charset='utf-8') -> dict:
    return json.loads(urlsafe_b64decode(to_bytes(text, charset)))


def generate_token(length=30):
    rand = random.SystemRandom()
    chars = string.ascii_letters + string.digits
    return ''.join(rand.choice(chars) for _ in range(length))

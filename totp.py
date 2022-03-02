import base64
import hmac
import math
from getpass import getpass
from hashlib import sha1
from time import time
from typing import Callable, Optional


def calc_T(current_unix_time: Optional[float] = None, T0: int = 0, X: int = 30) -> int:
    """calculate time step between the initial counter time T0 and the current Unix time

    Args:
        current_unix_time (float, optional): The current unix time. Defaults to None.
        T0 (int, optional): The initial counter time. Defaults to 0.
        X (int, optional): the time step in seconds. Defaults to 30.

    Returns:
        int: time step between T0 and X
    """
    if current_unix_time is None:
        current_unix_time = time()
    return math.floor((current_unix_time - T0) / X)


def calc_HOTP(secret: bytes, C: int, digestmod: Optional[Callable] = sha1, digits: Optional[int] = 6) -> str:
    """calculate hotp

    Args:
        secret (bytes): secret value
        C (int): counter value
        digestmod (Optional[Callable], optional): hash function. Defaults to sha1.
        digits (Optional[int], optional): digits of return value. Defaults to 6.

    Returns:
        str: hotp value
    """
    hs = hmac.new(secret, C.to_bytes(8, "big"), digestmod=digestmod).digest()
    offset = hs[len(hs) - 1] & 0x0F
    otp = (
        ((hs[offset] & 0x7F) << 24)
        | ((hs[offset + 1] & 0xFF) << 16)
        | ((hs[offset + 2] & 0xFF) << 8)
        | ((hs[offset + 3] & 0xFF))
    )
    return str(otp % 10 ** digits).zfill(6)


def calc_TOTP(
    b32encoded_secret: str, digestmod: Optional[Callable] = sha1, digits: Optional[int] = 6, period: int = 30
) -> str:
    """calculate totp using current unix time

    Args:
        b32encoded_secret (str): secret value encode with base32
        digestmod (Optional[Callable], optional): hash function. Defaults to sha1.
        digits (Optional[int], optional): digits of return value. Defaults to 6.
        period (int, optional): time step. Defaults to 30.

    Returns:
        str: totp value
    """
    secret = base64.b32decode(b32encoded_secret)
    return calc_HOTP(secret, calc_T(X=period), digestmod, digits)


if __name__ == "__main__":
    b32encoded_secret = getpass("Secret: ").strip()
    totp = calc_TOTP(b32encoded_secret)
    print(f"TOTP: {totp}")

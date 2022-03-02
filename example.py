import re
from hashlib import *
from typing import Callable, Optional
from urllib.parse import parse_qs

import cv2

from totp import calc_TOTP


def read_qrcode(qrcode_path: str) -> str:
    """read qrcode

    Args:
        qrcode_path (str): path to qrcode image

    Returns:
        str: data string
    """
    img = cv2.imread(qrcode_path)
    reader = cv2.QRCodeDetector()
    data, *_ = reader.detectAndDecode(img)
    return data


def import_hashlib(digestmod: str) -> Callable:
    """import hash function from string parameter.
    "sha1" => <function hashlib.sha1>

    Args:
        digestmod (str): string parameter deciding hash algorithm

    Raises:
        NotImplementedError: when hash algorithm is not implemented in hashlib

    Returns:
        Callable: hash function
    """
    try:
        return globals()[digestmod.lower()]
    except KeyError:
        raise NotImplementedError(f"The hash algolithm {digestmod} is not supported.")


def parse_otpauth_uri(uri: str) -> dict:
    """parse otpauth uri and format it properly

    Args:
        uri (str): otpauth uri

    Raises:
        ValueError: when format of otpauth uri is invalid

    Returns:
        dict: formatted parameters
    """
    if not (match := re.match("otpauth://(?P<type>[a-zA-Z]+?)/(?P<label>[a-zA-Z0-9]+?)\?(?P<query>.+?)$", uri)):
        raise ValueError("Invalid otpauth uri")

    query = parse_qs(match.group("query"))
    parameters = {k: v[0] for k, v in query.items()}

    try:
        parameters["digits"] = int(parameters["digits"])
        parameters["period"] = int(parameters["period"])
        parameters["algorithm"] = import_hashlib(parameters["algorithm"])
    except KeyError:
        raise ValueError("Required parameters are missing")
    parameters["type"] = match.group("type")
    parameters["label"] = match.group("label")

    return parameters


def main(urcode_path: Optional[str] = "./totp_qrcode.png") -> None:
    """example program of calculating totp from qrcode

    Args:
        urcode_path (Optional[str], optional): Path to qrcode image. Defaults to "./totp_qrcode.png".
    """
    uri = read_qrcode(urcode_path)
    parameters = parse_otpauth_uri(uri)
    totp = calc_TOTP(parameters["secret"], **parameters)
    print(totp)


if __name__ == "__main__":
    main()

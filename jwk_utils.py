"""
jwk_utils.py

Small helper to turn an RSA public key into a JWK dict, per RFC 7517.
"""

import base64


def _b64url_uint(value: int) -> str:
    """Base64url-encode an integer (no padding), as JWK requires for n/e."""
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")


def public_key_to_jwk(public_key, kid: str) -> dict:
    """Convert a cryptography RSA public key object into a JWK dict."""
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }

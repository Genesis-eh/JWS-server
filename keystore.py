"""
keystore.py

Handles RSA key pair generation and storage for the JWKS server.

Each key has:
  - kid: a unique key identifier
  - private_key / public_key: the RSA key pair objects
  - expiry: a unix timestamp saying when the key should stop being
    considered valid for JWKS publication

We keep two keys in memory for this assignment:
  - one "good" key that has not expired yet
  - one "expired" key, used only when the client explicitly asks
    for an expired JWT (via the `expired` query param on /auth)
"""

import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class Key:
    """A single RSA key pair with an id and an expiry timestamp."""

    def __init__(self, expiry_offset_seconds: int):
        self.kid = str(uuid.uuid4())
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        # expiry_offset_seconds can be negative to create an
        # already-expired key
        self.expiry = int(time.time()) + expiry_offset_seconds

    def is_expired(self) -> bool:
        return int(time.time()) >= self.expiry

    def private_pem(self) -> bytes:
        """Private key in PEM format, used to sign JWTs."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


class KeyStore:
    """Holds the set of keys the server knows about."""

    def __init__(self):
        # valid for 1 hour from server start
        self.good_key = Key(expiry_offset_seconds=3600)
        # already expired 1 hour ago
        self.expired_key = Key(expiry_offset_seconds=-3600)

    def all_keys(self):
        return [self.good_key, self.expired_key]

    def unexpired_keys(self):
        return [k for k in self.all_keys() if not k.is_expired()]

    def get_key(self, kid: str):
        for k in self.all_keys():
            if k.kid == kid:
                return k
        return None

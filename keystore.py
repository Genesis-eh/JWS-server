"""
keystore.py

RSA key storage for the JWKS server, backed by SQLite.
Private keys are saved to the DB as PEM bytes so they survive restarts.
"""

import sqlite3
import time
from contextlib import closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_FILE = "totally_not_my_privateKeys.db"


class Key:
    """An RSA key pair loaded from (or about to be saved to) the DB."""

    def __init__(self, kid, private_key, expiry):
        self.kid = str(kid)  # JWT/JWKS want kid as a string
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.expiry = expiry

    def private_pem(self) -> bytes:
        """Private key as PKCS1 PEM, used to sign JWTs and to store in the DB."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )


class KeyStore:
    """Reads and writes keys in the SQLite file."""

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self._init_db()
        self._ensure_keys()

    def _connect(self):
        return sqlite3.connect(self.db_file)

    def _init_db(self):
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
                """
            )

    def _ensure_keys(self):
        """Make sure there is at least one valid and one expired key."""
        if not self._fetch_one(expired=False):
            self.add_key(3600)
        if not self._fetch_one(expired=True):
            self.add_key(-3600)

    def add_key(self, expiry_offset_seconds: int):
        """Generate a new key and save it. Negative offset = already expired."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expiry = int(time.time()) + expiry_offset_seconds
        pem = Key(0, private_key, expiry).private_pem()
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiry)
            )

    @staticmethod
    def _row_to_key(row) -> Key:
        kid, pem, exp = row
        private_key = serialization.load_pem_private_key(pem, password=None)
        return Key(kid, private_key, exp)

    def _fetch_one(self, expired: bool):
        now = int(time.time())
        if expired:
            query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
        else:
            query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
        with closing(self._connect()) as conn:
            row = conn.execute(query, (now,)).fetchone()
        return self._row_to_key(row) if row else None

    def get_key(self, expired: bool = False) -> Key:
        """Get one valid key, or one expired key if expired=True."""
        key = self._fetch_one(expired)
        if key is None:
            # e.g. server ran long enough that the valid key aged out
            self._ensure_keys()
            key = self._fetch_one(expired)
        return key

    def unexpired_keys(self):
        """All keys that have not expired yet, for the JWKS response."""
        now = int(time.time())
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ?", (now,)
            ).fetchall()
        return [self._row_to_key(r) for r in rows]

"""
Test suite for the JWKS server.

Covers:
  - JWKS endpoint returns only unexpired keys, in valid JWK format
  - /auth issues a JWT that verifies against the published JWKS key
  - /auth?expired=true issues a JWT signed with the expired key,
    which is NOT present in the JWKS, and whose exp claim is in the past
  - wrong HTTP methods are rejected
  - SQLite keystore behavior (saving, reading, persistence)
  - jwk_utils helper behavior
"""

import base64
import sqlite3
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import app as app_module
from keystore import KeyStore, Key
from jwk_utils import public_key_to_jwk, _b64url_uint


@pytest.fixture
def store(tmp_path):
    """A KeyStore backed by a throwaway DB file."""
    return KeyStore(str(tmp_path / "test_keys.db"))


@pytest.fixture
def client(store, monkeypatch):
    """Flask test client that uses the temp store instead of the real DB."""
    monkeypatch.setattr(app_module, "store", store)
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def count_rows(db_file):
    conn = sqlite3.connect(db_file)
    n = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    conn.close()
    return n


def public_pem(key):
    return key.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------
# JWKS endpoint
# ---------------------------------------------------------------------

def test_jwks_returns_200_and_json(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "keys" in body
    assert isinstance(body["keys"], list)


def test_jwks_only_contains_unexpired_kid(client, store):
    resp = client.get("/.well-known/jwks.json")
    kids = [k["kid"] for k in resp.get_json()["keys"]]

    assert store.get_key(expired=False).kid in kids
    assert store.get_key(expired=True).kid not in kids


def test_jwks_key_shape_is_valid_jwk(client):
    resp = client.get("/.well-known/jwks.json")
    key = resp.get_json()["keys"][0]

    for field in ("kty", "use", "alg", "kid", "n", "e"):
        assert field in key
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"


def test_jwks_wrong_method_rejected(client):
    resp = client.post("/.well-known/jwks.json")
    assert resp.status_code == 405


# ---------------------------------------------------------------------
# /auth endpoint
# ---------------------------------------------------------------------

def test_auth_returns_200_and_token(client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    assert token.count(".") == 2  # header.payload.signature


def test_auth_token_header_has_matching_kid(client, store):
    resp = client.post("/auth")
    header = jwt.get_unverified_header(resp.get_data(as_text=True))
    assert header["kid"] == store.get_key(expired=False).kid


def test_auth_token_verifies_with_published_public_key(client, store):
    resp = client.post("/auth")
    token = resp.get_data(as_text=True)

    good_key = store.get_key(expired=False)
    decoded = jwt.decode(token, public_pem(good_key), algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > time.time()


def test_auth_expired_query_param_uses_expired_key(client, store):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    header = jwt.get_unverified_header(resp.get_data(as_text=True))
    assert header["kid"] == store.get_key(expired=True).kid


def test_auth_expired_token_has_past_exp_claim(client):
    resp = client.post("/auth?expired=true")
    token = resp.get_data(as_text=True)
    unverified = jwt.decode(token, options={"verify_signature": False})
    assert unverified["exp"] < time.time()


def test_auth_expired_key_not_in_jwks(client):
    auth_resp = client.post("/auth?expired=true")
    header = jwt.get_unverified_header(auth_resp.get_data(as_text=True))

    jwks_resp = client.get("/.well-known/jwks.json")
    kids_in_jwks = [k["kid"] for k in jwks_resp.get_json()["keys"]]

    assert header["kid"] not in kids_in_jwks


def test_auth_expired_signature_still_verifies_with_expired_public_key(
        client, store):
    """The key is expired and not published, but the signature should
    still verify against that specific key."""
    resp = client.post("/auth?expired=true")
    token = resp.get_data(as_text=True)

    expired_key = store.get_key(expired=True)
    decoded = jwt.decode(
        token,
        public_pem(expired_key),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert decoded["sub"] == "fake-user"


def test_auth_wrong_method_rejected(client):
    resp = client.get("/auth")
    assert resp.status_code == 405


# ---------------------------------------------------------------------
# keystore.py (SQLite)
# ---------------------------------------------------------------------

def test_keystore_creates_db_file(tmp_path):
    db = tmp_path / "new.db"
    KeyStore(str(db))
    assert db.exists()


def test_keystore_seeds_two_keys(store):
    assert count_rows(store.db_file) == 2


def test_keystore_valid_key_expires_in_future(store):
    assert store.get_key(expired=False).expiry > time.time()


def test_keystore_expired_key_expires_in_past(store):
    assert store.get_key(expired=True).expiry <= time.time()


def test_keystore_unexpired_keys_excludes_expired(store):
    unexpired = store.unexpired_keys()
    kids = [k.kid for k in unexpired]
    assert store.get_key(expired=False).kid in kids
    assert store.get_key(expired=True).kid not in kids


def test_keystore_kid_is_string(store):
    assert isinstance(store.get_key().kid, str)


def test_keystore_keys_persist_across_restart(store):
    kid_before = store.get_key(expired=False).kid
    reopened = KeyStore(store.db_file)
    assert count_rows(store.db_file) == 2  # no new keys generated
    assert reopened.get_key(expired=False).kid == kid_before


def test_keystore_add_key_inserts_row(store):
    store.add_key(7200)
    assert count_rows(store.db_file) == 3


def test_keystore_regenerates_when_db_empty(store):
    conn = sqlite3.connect(store.db_file)
    conn.execute("DELETE FROM keys")
    conn.commit()
    conn.close()

    assert store.get_key(expired=False) is not None
    assert store.get_key(expired=True) is not None


def test_key_private_pem_is_pem_bytes():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    k = Key(1, private_key, int(time.time()) + 60)
    assert k.private_pem().startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_key_round_trips_through_db(store):
    """A key saved as PEM and loaded back should be a usable RSA key."""
    key = store.get_key(expired=False)
    assert key.private_key.key_size == 2048


# ---------------------------------------------------------------------
# jwk_utils.py
# ---------------------------------------------------------------------

def test_public_key_to_jwk_fields():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    jwk = public_key_to_jwk(private_key.public_key(), "test-kid")

    assert jwk["kid"] == "test-kid"
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert isinstance(jwk["n"], str)
    assert isinstance(jwk["e"], str)


def test_b64url_uint_no_padding():
    encoded = _b64url_uint(65537)
    assert "=" not in encoded
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded_bytes = base64.urlsafe_b64decode(padded)
    assert int.from_bytes(decoded_bytes, "big") == 65537

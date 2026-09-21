"""
Test suite for the JWKS server.

Covers:
  - JWKS endpoint returns only unexpired keys, in valid JWK format
  - /auth issues a JWT that verifies against the published JWKS key
  - /auth?expired=true issues a JWT signed with the expired key,
    which is NOT present in the JWKS, and whose exp claim is in the past
  - wrong HTTP methods are rejected
  - keystore / jwk_utils helper behavior
"""

import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import app as app_module
from keystore import KeyStore, Key
from jwk_utils import public_key_to_jwk, _b64url_uint


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


# ---------------------------------------------------------------------
# JWKS endpoint
# ---------------------------------------------------------------------

def test_jwks_returns_200_and_json(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "keys" in body
    assert isinstance(body["keys"], list)


def test_jwks_only_contains_unexpired_kid(client):
    resp = client.get("/.well-known/jwks.json")
    body = resp.get_json()
    kids = [k["kid"] for k in body["keys"]]

    assert app_module.store.good_key.kid in kids
    assert app_module.store.expired_key.kid not in kids


def test_jwks_key_shape_is_valid_jwk(client):
    resp = client.get("/.well-known/jwks.json")
    body = resp.get_json()
    key = body["keys"][0]

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


def test_auth_token_header_has_matching_kid(client):
    resp = client.post("/auth")
    token = resp.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == app_module.store.good_key.kid


def test_auth_token_verifies_with_published_public_key(client):
    from cryptography.hazmat.primitives import serialization

    resp = client.post("/auth")
    token = resp.get_data(as_text=True)

    good_key = app_module.store.good_key
    public_pem = good_key.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > time.time()


def test_auth_expired_query_param_uses_expired_key(client):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == app_module.store.expired_key.kid


def test_auth_expired_token_has_past_exp_claim(client):
    resp = client.post("/auth?expired=true")
    token = resp.get_data(as_text=True)
    unverified = jwt.decode(token, options={"verify_signature": False})
    assert unverified["exp"] < time.time()


def test_auth_expired_key_not_in_jwks(client):
    auth_resp = client.post("/auth?expired=true")
    token = auth_resp.get_data(as_text=True)
    header = jwt.get_unverified_header(token)

    jwks_resp = client.get("/.well-known/jwks.json")
    kids_in_jwks = [k["kid"] for k in jwks_resp.get_json()["keys"]]

    assert header["kid"] not in kids_in_jwks


def test_auth_expired_signature_still_verifies_with_expired_public_key(client):
    """Even though the key has 'expired' and isn't published, the
    signature itself should still be cryptographically valid against
    that specific key -- proving we really signed with it."""
    resp = client.post("/auth?expired=true")
    token = resp.get_data(as_text=True)

    expired_key = app_module.store.expired_key
    from cryptography.hazmat.primitives import serialization

    public_pem = expired_key.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    decoded = jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert decoded["sub"] == "fake-user"


def test_auth_wrong_method_rejected(client):
    resp = client.get("/auth")
    assert resp.status_code == 405


# ---------------------------------------------------------------------
# keystore.py
# ---------------------------------------------------------------------

def test_key_generates_unique_kid():
    k1 = Key(expiry_offset_seconds=60)
    k2 = Key(expiry_offset_seconds=60)
    assert k1.kid != k2.kid


def test_key_is_expired_true_for_past_offset():
    k = Key(expiry_offset_seconds=-10)
    assert k.is_expired() is True


def test_key_is_expired_false_for_future_offset():
    k = Key(expiry_offset_seconds=600)
    assert k.is_expired() is False


def test_key_private_pem_is_pem_bytes():
    k = Key(expiry_offset_seconds=60)
    pem = k.private_pem()
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")


def test_keystore_all_keys_returns_both():
    ks = KeyStore()
    assert len(ks.all_keys()) == 2


def test_keystore_unexpired_keys_excludes_expired():
    ks = KeyStore()
    unexpired = ks.unexpired_keys()
    assert ks.good_key in unexpired
    assert ks.expired_key not in unexpired


def test_keystore_get_key_found():
    ks = KeyStore()
    found = ks.get_key(ks.good_key.kid)
    assert found is ks.good_key


def test_keystore_get_key_not_found():
    ks = KeyStore()
    assert ks.get_key("not-a-real-kid") is None


# ---------------------------------------------------------------------
# jwk_utils.py
# ---------------------------------------------------------------------

def test_public_key_to_jwk_fields():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = public_key_to_jwk(public_key, "test-kid")

    assert jwk["kid"] == "test-kid"
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert isinstance(jwk["n"], str)
    assert isinstance(jwk["e"], str)


def test_b64url_uint_no_padding():
    encoded = _b64url_uint(65537)
    assert "=" not in encoded
    # round-trip check
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded_bytes = base64.urlsafe_b64decode(padded)
    assert int.from_bytes(decoded_bytes, "big") == 65537

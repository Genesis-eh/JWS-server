"""
app.py

A basic JWKS (JSON Web Key Set) server.

Endpoints:
  GET  /.well-known/jwks.json   -> publishes unexpired public keys as a JWKS
  POST /auth                    -> issues a signed JWT
                                    (add ?expired=true to get one signed
                                    with an expired key/expiry, for testing)

Run with:
    python app.py
Server listens on port 8080.
"""

import time

import jwt
from flask import Flask, jsonify, request

from keystore import KeyStore
from jwk_utils import public_key_to_jwk

app = Flask(__name__)

# One process-wide key store. In a real system this would be backed by
# a database / HSM and keys would be rotated on a schedule instead of
# being generated once at startup.
store = KeyStore()


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serve the JWKS containing only keys that have not expired."""
    keys = [public_key_to_jwk(k.public_key, k.kid) for k in store.unexpired_keys()]
    return jsonify({"keys": keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """
    Mock authentication endpoint.

    We don't actually validate credentials for this assignment -- any
    POST here is treated as a successful login and gets back a JWT.

    If the "expired" query parameter is present, the JWT is signed
    with the already-expired key, and its `exp` claim is set in the
    past, so a verifier checking either the key or the claim will see
    it as expired.
    """
    use_expired = "expired" in request.args

    key = store.expired_key if use_expired else store.good_key

    now = int(time.time())
    if use_expired:
        issued_at = now - 7200
        expires_at = key.expiry  # already in the past
    else:
        issued_at = now
        expires_at = now + 3600

    payload = {
        "sub": "fake-user",
        "iat": issued_at,
        "exp": expires_at,
    }

    token = jwt.encode(
        payload,
        key.private_pem(),
        algorithm="RS256",
        headers={"kid": key.kid},
    )

    # PyJWT >= 2 returns a str already; older versions return bytes.
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return token, 200, {"Content-Type": "text/plain"}


@app.route("/auth", methods=["GET", "PUT", "DELETE", "PATCH"])
def auth_wrong_method():
    """Reject non-POST methods on /auth with 405, as a RESTful API should."""
    return jsonify({"error": "method not allowed"}), 405


@app.route("/.well-known/jwks.json", methods=["POST", "PUT", "DELETE", "PATCH"])
def jwks_wrong_method():
    """Reject non-GET methods on the JWKS endpoint with 405."""
    return jsonify({"error": "method not allowed"}), 405


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

# JWKS Server — CSCE 3550 Project 1

**Author:** Genesis Enemuoh ([github.com/Genesis-eh](https://github.com/Genesis-eh))

A basic JWKS (JSON Web Key Set) server built with Python and Flask. It generates
RSA key pairs, publishes public keys with a `kid` and expiry, and issues signed
JWTs — including a way to get a JWT signed with an already-expired key for
testing verification failure paths.

## What it does

- Generates two RSA key pairs on startup:
  - one valid key (expires 1 hour from server start)
  - one already-expired key (expired 1 hour before server start)
- `GET /.well-known/jwks.json` — publishes only the **unexpired** public
  keys, in standard JWK format (`kty`, `use`, `alg`, `kid`, `n`, `e`).
- `POST /auth` — returns a JWT signed with the valid key, `kid` in the
  header, expiring 1 hour from now.
- `POST /auth?expired=true` — returns a JWT signed with the expired key,
  with an `exp` claim already in the past. That key is intentionally left
  out of the JWKS response.
- Wrong HTTP methods on either endpoint return `405`.

## Project layout

```
app.py           Flask app / route handlers
keystore.py      RSA key generation + expiry tracking
jwk_utils.py     RSA public key -> JWK dict conversion
tests/test_app.py  Test suite (pytest)
requirements.txt
```

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Server listens on `http://localhost:8080`.

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest tests/ --cov=. --cov-report=term-missing -v
```

22 tests, 99% coverage (see `screenshots/pytest_coverage.png`).

## Linting

```bash
python -m flake8 --max-line-length=100 app.py keystore.py jwk_utils.py tests/test_app.py
```

No warnings.

## Blackbox testing

Tested against the official [CSCE3550 gradebot client](https://github.com/jh125486/CSCE3550/releases):

```bash
./gradebot project-1 --dir=. --run="python3 app.py" --port=8080
```

Result: **92.86%** — every functional check (valid JWT auth, expired JWT
auth, HTTP methods/status codes, valid JWK in JWKS, expired JWT actually
expired, expired JWK excluded from JWKS) passed at 100%. The only missed
points are the 5-point "Quality" check, which calls out to an external
grading server for an automated code-quality pass — that outbound call
was blocked in the sandboxed environment this was built in
(`403 Forbidden`), not a failure of the code itself. See
`screenshots/gradebot_run.png`.

## Notes

- This is for educational purposes only — the `/auth` endpoint doesn't
  actually check credentials, per the assignment spec (any POST is treated
  as a successful "login").
- In a real system, keys would be rotated on a schedule and stored
  somewhere more durable than process memory (a DB or HSM), and you'd
  want a real authentication layer in front of `/auth`.

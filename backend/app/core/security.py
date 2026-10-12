"""Password hashing and token helpers."""

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id with argon2-cffi's RFC 9106 "low memory" defaults.
_hasher = PasswordHasher()

# Verified against when the username doesn't exist, so response time doesn't
# reveal which usernames are valid.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-work verification. A None hash still performs a full Argon2 check."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_token() -> str:
    """256 bits of randomness, URL-safe."""
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    """SHA-256 hex digest. Session and CSRF tokens are stored only in this form."""
    return hashlib.sha256(token.encode()).hexdigest()


def digests_match(token: str, expected_digest: str) -> bool:
    return hmac.compare_digest(token_digest(token), expected_digest)

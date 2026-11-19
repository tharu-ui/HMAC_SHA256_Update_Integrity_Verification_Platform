import hashlib
import hmac
import re
import secrets

PBKDF2_ITERATIONS = 600_000
SESSION_TTL = 8 * 3600
MAX_FAILURES = 5
LOCK_SECONDS = 300
ROLES = ("admin", "publisher", "verifier")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


DUMMY_HASH = hash_password("timing-equaliser")  # used so unknown usernames cost the same time as real ones


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()  # only the hash is stored server-side


def validate_password(password: str):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if len(password) > 128:
        raise ValueError("Password is too long.")

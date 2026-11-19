import hashlib
import hmac
import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path, PurePosixPath

MAX_PACKAGE_BYTES = 30 * 1024 * 1024
MAX_FILES = 300
MAX_UNCOMPRESSED = 100 * 1024 * 1024
KEYS_PATH = Path("data/keys.json")
LEGACY_KEY_ID = "local-demo-key"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------- keyring
def _load_keyring():
    if KEYS_PATH.exists():
        return json.loads(KEYS_PATH.read_text(encoding="utf-8"))
    secret = os.getenv("APP_SECRET", "LOCAL-ACADEMIC-DEMO-KEY-change-me-2026")
    ring = {"active": LEGACY_KEY_ID,
            "keys": {LEGACY_KEY_ID: {"secret": secret, "created_at": utc_now()}}}
    _save_keyring(ring)
    return ring


def _save_keyring(ring):
    KEYS_PATH.parent.mkdir(exist_ok=True)
    KEYS_PATH.write_text(json.dumps(ring, indent=2), encoding="utf-8")


def active_key_id() -> str:
    return _load_keyring()["active"]


def key_exists(key_id) -> bool:
    return key_id in _load_keyring()["keys"]


def get_secret(key_id: str | None = None) -> bytes:
    ring = _load_keyring()
    entry = ring["keys"].get(key_id or ring["active"])
    if not entry:
        raise KeyError(f"Unknown key id: {key_id}")
    return entry["secret"].encode("utf-8")


def list_keys():
    ring = _load_keyring()
    return {"active": ring["active"], "keys": [
        {"key_id": k, "created_at": v["created_at"], "active": k == ring["active"],
         "fingerprint": sha256_bytes(v["secret"].encode())[:16]}  # never expose the secret itself
        for k, v in ring["keys"].items()]}


def rotate_key() -> str:
    """Create a new active key. Old keys stay in the ring so older releases remain verifiable."""
    ring = _load_keyring()
    new_id = f"key-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3)}"
    ring["keys"][new_id] = {"secret": secrets.token_hex(32), "created_at": utc_now()}
    ring["active"] = new_id
    _save_keyring(ring)
    return new_id


# ---------------------------------------------------------------- HMAC
def hmac_hex(payload: bytes, key_id: str | None = None) -> str:
    return hmac.new(get_secret(key_id), payload, hashlib.sha256).hexdigest()


def verify_hmac(payload: bytes, supplied: str, key_id: str | None = None) -> bool:
    try:
        expected = hmac_hex(payload, key_id)
    except KeyError:
        return False
    return hmac.compare_digest(expected, (supplied or "").strip().lower())


# ---------------------------------------------------------------- packages
def safe_zip_manifest(package: bytes):
    if len(package) > MAX_PACKAGE_BYTES:
        raise ValueError("Package exceeds the 30 MB demo limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(package))
    except zipfile.BadZipFile:
        raise ValueError("The uploaded file is not a valid ZIP package.")
    infos = archive.infolist()
    if len(infos) > MAX_FILES:
        raise ValueError("Package contains too many entries.")
    if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
        raise ValueError("Expanded package exceeds the 100 MB safety limit.")
    manifest = {}
    for info in infos:
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        mode = (info.external_attr >> 16) & 0o170000
        if path.is_absolute() or ".." in path.parts or not name or name.startswith("/"):
            raise ValueError(f"Unsafe ZIP path rejected: {name}")
        if mode == 0o120000:
            raise ValueError(f"Symbolic link rejected: {name}")
        if info.flag_bits & 0x1:
            raise ValueError(f"Encrypted ZIP entry rejected: {name}")
        if info.is_dir():
            continue
        content = archive.read(info)
        manifest[name] = {"sha256": sha256_bytes(content), "size": len(content)}
    return dict(sorted(manifest.items()))


def create_sample_package(app_name="Northstar Notes", version="1.0.0"):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("client/app_config.json", json.dumps(
            {"app": app_name, "channel": "stable", "feature_flags": ["sync", "offline"]}, indent=2) + "\n")
        z.writestr("client/release.txt", f"{app_name} {version}\nRelease: stable\n")
        z.writestr("docs/CHANGELOG.md", f"# Release {version}\n\nVerified demonstration release.\n")
    return memory.getvalue()


def tamper_package(original: bytes) -> bytes:
    """Append bytes to the first file in the ZIP (attack simulation only)."""
    source = zipfile.ZipFile(io.BytesIO(original))
    output, changed = io.BytesIO(), False
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if not changed and not item.is_dir():
                data += b"\n# DEMO TAMPER: unauthorized modification\n"
                changed = True
            target.writestr(item, data)
    if not changed:
        raise ValueError("No file available to modify.")
    return output.getvalue()


def make_envelope(package: bytes, app_name: str, version: str, expires_in_hours: float = 0):
    manifest = safe_zip_manifest(package)
    key_id = active_key_id()
    expires = None
    if expires_in_hours:
        expires = (datetime.now(timezone.utc) + timedelta(hours=float(expires_in_hours))).isoformat()
    envelope = {
        "schema": "hmac-update-envelope/v1",
        "app_name": app_name.strip()[:80],
        "version": version.strip()[:40],
        "update_id": secrets.token_hex(12),
        "created_at": utc_now(),
        "expires_at": expires,
        "key_id": key_id,
        "package_sha256": sha256_bytes(package),
        "manifest": manifest,
    }
    return envelope, hmac_hex(canonical_json(envelope), key_id)


def is_expired(envelope: dict) -> bool:
    value = envelope.get("expires_at")
    if not value:
        return False
    try:
        return datetime.fromisoformat(value) < datetime.now(timezone.utc)
    except ValueError:
        return True  # unparsable expiry is treated as expired (fail closed)


def analyze_package(package: bytes, envelope: dict):
    actual = safe_zip_manifest(package)
    expected = envelope.get("manifest", {})
    expected_names, actual_names = set(expected), set(actual)
    changed = sorted(n for n in expected_names & actual_names if expected[n].get("sha256") != actual[n].get("sha256"))
    missing = sorted(expected_names - actual_names)
    added = sorted(actual_names - expected_names)
    return {"changed_files": changed, "missing_files": missing, "unexpected_files": added,
            "manifest_match": not (changed or missing or added), "actual_manifest": actual}

import copy
import csv
import io
import json
import os
import secrets
import time
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
from pydantic import BaseModel
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()
from . import database as db
from . import auth
from .demo import build_trace
from .security import (
    create_sample_package, make_envelope, canonical_json, hmac_hex, verify_hmac, analyze_package,
    sha256_bytes, tamper_package, is_expired, key_exists, list_keys, rotate_key, active_key_id, safe_zip_manifest,
)

BASE = Path(__file__).resolve().parent
DATA = Path("data")
DATA.mkdir(exist_ok=True)
PACKAGES = DATA / "packages"
PACKAGES.mkdir(exist_ok=True)
LAB_APP = "Attack Lab Sandbox"

app = FastAPI(title="HMAC Update Integrity Platform", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
                   allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.on_event("startup")
def startup():
    db.init_db()
    db.init_auth_tables()
    seed_admin()


def seed_admin():
    """Create the first admin account. Password comes from ADMIN_PASSWORD or is generated and printed once."""
    if db.user_count():
        return
    password = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(9)
    db.create_user("admin", auth.hash_password(password), "admin")
    if not os.getenv("ADMIN_PASSWORD"):
        print("\n" + "=" * 60 + f"\n  FIRST RUN: admin account created\n  username: admin\n  password: {password}\n  (shown once - change it after signing in)\n" + "=" * 60 + "\n")


COOKIE = "nsid"


def current_user(request: Request):
    token = request.cookies.get(COOKIE)
    user = db.get_session_user(auth.token_hash(token), time.time()) if token else None
    if not user:
        raise HTTPException(401, "Not signed in.")
    return user


def require(*roles):
    def dep(user=Depends(current_user)):
        if user["role"] != "admin" and user["role"] not in roles:
            raise HTTPException(403, f"Your role ({user['role']}) is not allowed to do this.")
        return user
    return dep


def start_session(response: Response, user_id: int):
    token = auth.new_token()
    db.create_session(auth.token_hash(token), user_id, auth.SESSION_TTL, time.time())
    response.set_cookie(COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, samesite="strict", path="/")


@app.get("/")
def home():
    return FileResponse(BASE / "static" / "index.html")


# ------------------------------------------------------------ helpers
def version_key(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (0,)


def run_verification(package_bytes: bytes, envelope_data: dict, accept: bool = False, actor: str = "system"):
    """Full verification pipeline. Returns the result dict and writes an audit event."""
    envelope, supplied_tag = envelope_data["envelope"], envelope_data["hmac"]
    manifest_result = analyze_package(package_bytes, envelope)
    key_id = envelope.get("key_id")
    key_known = key_exists(key_id)
    tag_valid = key_known and verify_hmac(canonical_json(envelope), supplied_tag, key_id)
    package_hash_valid = sha256_bytes(package_bytes) == envelope.get("package_sha256")
    manifest_valid = manifest_result["manifest_match"]
    app_name, version, update_id = envelope.get("app_name", "Unknown"), envelope.get("version", "?"), envelope.get("update_id", "")
    expired = is_expired(envelope)
    replay = db.was_seen(update_id)
    latest = db.get_latest_version(app_name)
    rollback = bool(latest and version_key(version) <= version_key(latest))

    reasons = []
    if not key_known: reasons.append(f"Unknown signing key '{key_id}': no matching key in the keyring.")
    if not tag_valid and key_known: reasons.append("HMAC authentication failed: envelope or metadata was changed.")
    if not package_hash_valid: reasons.append("Package fingerprint differs from the signed package fingerprint.")
    if not manifest_valid:
        if manifest_result["changed_files"]: reasons.append("Modified files: " + ", ".join(manifest_result["changed_files"]))
        if manifest_result["missing_files"]: reasons.append("Missing files: " + ", ".join(manifest_result["missing_files"]))
        if manifest_result["unexpected_files"]: reasons.append("Unexpected files: " + ", ".join(manifest_result["unexpected_files"]))
    if expired: reasons.append(f"Update expired at {envelope.get('expires_at')}.")
    if replay: reasons.append("Replay detected: this update ID has already been accepted.")
    if rollback: reasons.append(f"Rollback blocked: current accepted version is {latest}.")

    integrity_ok = key_known and tag_valid and package_hash_valid and manifest_valid
    valid = integrity_ok and not expired and not replay and not rollback
    if valid: status = "ACCEPTED"
    elif not integrity_ok: status = "REJECTED"
    elif expired: status = "EXPIRED"
    elif replay: status = "REPLAY_BLOCKED"
    else: status = "ROLLBACK_BLOCKED"

    if valid and accept:
        db.accept_update(app_name, version, update_id)
        reasons.append("Update accepted and version state recorded.")
    elif valid:
        reasons.append("Cryptographically valid. Select 'Accept update' to record this version as installed.")

    db.log_event("verification", status, app_name, version, {
        "actor": actor, "update_id": update_id, "key_id": key_id, "hmac_valid": tag_valid, "package_hash_valid": package_hash_valid,
        "manifest_valid": manifest_valid, "expired": expired, "replay": replay, "rollback": rollback,
        "changed_files": manifest_result["changed_files"], "missing_files": manifest_result["missing_files"],
        "unexpected_files": manifest_result["unexpected_files"], "accepted": bool(valid and accept)})
    return {
        "status": status, "valid": valid, "accepted": bool(valid and accept),
        "checks": {"hmac": tag_valid, "key_trust": key_known, "package_fingerprint": package_hash_valid,
                   "file_manifest": manifest_valid, "freshness": not expired,
                   "replay_protection": not replay, "rollback_protection": not rollback},
        "reasons": reasons, "changed_files": manifest_result["changed_files"],
        "missing_files": manifest_result["missing_files"], "unexpected_files": manifest_result["unexpected_files"],
        "app_name": app_name, "version": version, "update_id": update_id, "key_id": key_id,
        "expires_at": envelope.get("expires_at"), "latest_accepted_version": latest,
    }


def publish(package: bytes, app_name: str, version: str, expires_in_hours: float = 0, actor: str = "system"):
    envelope, tag = make_envelope(package, app_name, version, expires_in_hours)
    uid = envelope["update_id"]
    (PACKAGES / f"{uid}.zip").write_bytes(package)
    (PACKAGES / f"{uid}.json").write_text(json.dumps({"envelope": envelope, "hmac": tag}, indent=2), encoding="utf-8")
    db.log_event("publication", "CREATED", envelope["app_name"], envelope["version"],
                 {"actor": actor, "update_id": uid, "package_sha256": envelope["package_sha256"], "key_id": envelope["key_id"]})
    return {"message": "Update signed and packaged.", "update_id": uid, "app_name": envelope["app_name"],
            "version": envelope["version"], "package_sha256": envelope["package_sha256"], "hmac": tag,
            "key_id": envelope["key_id"], "expires_at": envelope["expires_at"],
            "file_count": len(envelope["manifest"]), "package_url": f"/api/download/{uid}", "envelope": envelope}


# ------------------------------------------------------------ routes
@app.get("/api/overview")
def overview(user=Depends(current_user)):
    return {"stats": db.get_stats(), "audit": db.get_audit(8), "keys": list_keys()["active"]}


@app.get("/api/audit")
def audit(user=Depends(current_user)):
    return {"items": db.get_audit(500)}


@app.get("/api/audit/chain")
def audit_chain(user=Depends(current_user)):
    return db.verify_chain()


@app.get("/api/audit.csv")
def audit_csv(user=Depends(current_user)):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "created_at", "event", "app_name", "version", "status", "detail", "entry_hash"])
    for r in reversed(db.get_audit(5000)):
        w.writerow([r["id"], r["created_at"], r["event"], r["app_name"], r["version"], r["status"], r["detail"], r.get("entry_hash")])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="audit-trail.csv"'})


@app.get("/api/report")
def report(user=Depends(current_user)):
    payload = {"generated_for": "HMAC Update Integrity Platform", "stats": db.get_stats(),
               "audit_chain": db.verify_chain(), "events": db.get_audit(500)}
    return JSONResponse(payload, headers={"Content-Disposition": 'attachment; filename="security-audit-report.json"'})


@app.post("/api/publisher/sample")
def publish_sample(app_name: str = "Northstar Notes", version: str = "1.0.0", expires_in_hours: float = 0,
                   user=Depends(require("publisher"))):
    return publish(create_sample_package(app_name, version), app_name, version, expires_in_hours, user["username"])


@app.post("/api/publisher/upload")
async def publish_upload(package: UploadFile = File(...), app_name: str = Form("Custom App"),
                         version: str = Form("1.0.0"), expires_in_hours: float = Form(0), user=Depends(require("publisher"))):
    try:
        return publish(await package.read(), app_name, version, expires_in_hours, user["username"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/releases")
def releases(user=Depends(current_user)):
    items = []
    for path in sorted(PACKAGES.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:25]:
        try:
            env = json.loads(path.read_text(encoding="utf-8"))["envelope"]
        except Exception:
            continue
        items.append({"update_id": env["update_id"], "app_name": env["app_name"], "version": env["version"],
                      "created_at": env["created_at"], "expires_at": env.get("expires_at"),
                      "key_id": env.get("key_id"), "files": len(env.get("manifest", {}))})
    return {"items": items}


def _safe_id(update_id: str) -> Path:
    if not update_id.isalnum():
        raise HTTPException(400, "Invalid update id.")
    return PACKAGES / update_id


@app.get("/api/download/{update_id}")
def download(update_id: str, user=Depends(current_user)):
    path = _safe_id(update_id).with_suffix(".zip")
    if not path.exists():
        raise HTTPException(404, "Package not found.")
    return FileResponse(path, filename=f"update-{update_id}.zip", media_type="application/zip")


@app.get("/api/envelope/{update_id}")
def download_envelope(update_id: str, user=Depends(current_user)):
    path = _safe_id(update_id).with_suffix(".json")
    if not path.exists():
        raise HTTPException(404, "Envelope not found.")
    return FileResponse(path, filename=f"update-{update_id}.json", media_type="application/json")


@app.post("/api/verify")
async def verify(package: UploadFile = File(...), envelope_file: UploadFile = File(...), accept: bool = Form(False),
                 user=Depends(require("verifier"))):
    try:
        package_bytes = await package.read()
        envelope_data = json.loads((await envelope_file.read()).decode("utf-8"))
        envelope_data["envelope"], envelope_data["hmac"]
        return run_verification(package_bytes, envelope_data, accept, user["username"])
    except Exception as exc:
        db.log_event("verification", "INVALID_PACKAGE", detail={"error": str(exc)})
        raise HTTPException(400, f"Could not inspect submission: {exc}")


@app.post("/api/attack/tamper")
async def tamper(package: UploadFile = File(...), user=Depends(require("verifier"))):
    try:
        return Response(tamper_package(await package.read()), media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="tampered-update.zip"'})
    except Exception as exc:
        raise HTTPException(400, str(exc))


# ------------------------------------------------------------ attack lab
def _lab_release(version, expires_in_hours=0):
    pkg = create_sample_package(LAB_APP, version)
    env, tag = make_envelope(pkg, LAB_APP, version, expires_in_hours)
    return pkg, {"envelope": env, "hmac": tag}


def _step(label, note, result):
    return {"label": label, "note": note, "status": result["status"], "valid": result["valid"],
            "checks": result["checks"], "reasons": result["reasons"]}


LAB_SCENARIOS = {
    "tamper": ("Package tampering", "A file inside the signed ZIP is modified in transit."),
    "forged": ("Forged metadata", "Attacker edits the envelope (version 9.9.9) but cannot recompute the HMAC."),
    "replay": ("Replay attack", "A previously accepted update is submitted again."),
    "rollback": ("Rollback / downgrade", "An older but validly signed release is pushed after a newer one."),
    "expired": ("Expired release", "A validly signed update is used after its expiry time."),
    "unknown_key": ("Unknown signing key", "Envelope claims a key id that is not in the trusted keyring."),
}


@app.post("/api/lab/run/{scenario}")
async def lab_run(scenario: str, package: Optional[UploadFile] = File(None), user=Depends(require("verifier"))):
    if scenario not in LAB_SCENARIOS:
        raise HTTPException(404, "Unknown scenario.")
    custom = await package.read() if package is not None and package.filename else None
    if custom is not None and len(custom) > 30 * 1024 * 1024:
        raise HTTPException(400, "Package is larger than 30 MB.")
    try:
        return _lab_simulate(scenario, custom, package.filename if custom is not None else None)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"Could not simulate on this package: {exc}")


def _lab_simulate(scenario, custom=None, filename=None):
    # Uploaded packages are always re-signed inside the sandbox app, so real application state is never touched.
    def _lab_release(version, expires_in_hours=0):
        pkg = custom if custom is not None else create_sample_package(LAB_APP, version)
        env, tag = make_envelope(pkg, LAB_APP, version, expires_in_hours)
        return pkg, {"envelope": env, "hmac": tag}
    db.reset_app(LAB_APP)  # sandbox state only; never touches real applications
    steps = []
    if scenario == "tamper":
        pkg, env = _lab_release("1.0.0")
        steps.append(_step("Attacker modifies a file", "Original envelope, modified ZIP", run_verification(tamper_package(pkg), env)))
    elif scenario == "forged":
        pkg, env = _lab_release("1.0.0")
        forged = copy.deepcopy(env)
        forged["envelope"]["version"] = "9.9.9"
        steps.append(_step("Envelope edited, HMAC unchanged", "Version changed 1.0.0 → 9.9.9", run_verification(pkg, forged)))
    elif scenario == "replay":
        pkg, env = _lab_release("1.0.0")
        steps.append(_step("First delivery", "Legitimate install", run_verification(pkg, env, accept=True)))
        steps.append(_step("Same update re-sent", "Identical package and envelope", run_verification(pkg, env, accept=True)))
    elif scenario == "rollback":
        pkg2, env2 = _lab_release("2.0.0")
        steps.append(_step("Install v2.0.0", "Newest release accepted", run_verification(pkg2, env2, accept=True)))
        pkg1, env1 = _lab_release("1.0.0")
        steps.append(_step("Push older v1.0.0", "Valid signature, older version", run_verification(pkg1, env1, accept=True)))
    elif scenario == "expired":
        pkg, env = _lab_release("1.0.0", expires_in_hours=-1)
        steps.append(_step("Use expired release", "Expired one hour ago", run_verification(pkg, env)))
    elif scenario == "unknown_key":
        pkg, env = _lab_release("1.0.0")
        env["envelope"]["key_id"] = "attacker-key-01"
        steps.append(_step("Envelope claims untrusted key", "key_id = attacker-key-01", run_verification(pkg, env)))
    title, desc = LAB_SCENARIOS[scenario]
    n_files = len(safe_zip_manifest(custom)) if custom is not None else 3
    return {"scenario": scenario, "title": title, "description": desc, "target": filename or "Sample bundle", "files": n_files,
            "blocked": all(not s["valid"] for s in steps[-1:]), "steps": steps}


# ------------------------------------------------------------ keys & tools
@app.get("/api/keys")
def keys(user=Depends(require("publisher"))):
    return list_keys()


@app.post("/api/keys/rotate")
def keys_rotate(user=Depends(require("admin"))):
    new_id = rotate_key()
    db.log_event("key_rotation", "ROTATED", detail={"actor": user["username"], "new_key_id": new_id})
    return {"message": "Key rotated.", "active": new_id, **list_keys()}


@app.post("/api/tools/hash")
async def hash_tool(text: str = Form(""), file: UploadFile | None = File(None), compare_tag: str = Form(""), user=Depends(require("publisher"))):
    data = await file.read() if file else text.encode("utf-8")
    kid = active_key_id()
    tag = hmac_hex(data, kid)
    out = {"bytes": len(data), "sha256": sha256_bytes(data), "hmac": tag, "key_id": kid}
    if compare_tag.strip():
        out["match"] = verify_hmac(data, compare_tag, kid)  # constant-time comparison
    return out


# ------------------------------------------------------------ authentication
class LoginBody(BaseModel):
    username: str
    password: str


class PasswordBody(BaseModel):
    current: str
    new: str


class NewUserBody(BaseModel):
    username: str
    password: str
    role: str


class ResetBody(BaseModel):
    password: str


@app.post("/api/auth/login")
def login(body: LoginBody, response: Response):
    name = body.username.strip()[:40]
    user = db.get_user_by_name(name)
    now = time.time()
    if user and user["locked_until"] > now:
        db.log_event("auth", "LOCKED", detail={"username": name})
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    ok = auth.check_password(body.password, user["password_hash"] if user else auth.DUMMY_HASH)
    if not (user and ok and user["active"]):
        if user:
            db.register_failure(user["id"], auth.MAX_FAILURES, auth.LOCK_SECONDS, now)
        db.log_event("auth", "LOGIN_FAILED", detail={"username": name})
        raise HTTPException(401, "Invalid username or password.")
    db.register_success(user["id"])
    start_session(response, user["id"])
    db.log_event("auth", "LOGIN_OK", detail={"actor": user["username"], "role": user["role"]})
    return {"username": user["username"], "role": user["role"]}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        db.delete_session(auth.token_hash(token))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"username": user["username"], "role": user["role"]}


@app.post("/api/auth/password")
def change_password(body: PasswordBody, response: Response, user=Depends(current_user)):
    row = db.get_user(user["id"])
    if not auth.check_password(body.current, row["password_hash"]):
        raise HTTPException(400, "Current password is incorrect.")
    try:
        auth.validate_password(body.new)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.set_password(user["id"], auth.hash_password(body.new))  # also signs out every other session
    start_session(response, user["id"])
    db.log_event("auth", "PASSWORD_CHANGED", detail={"actor": user["username"]})
    return {"ok": True}


@app.get("/api/users")
def users(user=Depends(require("admin"))):
    return {"items": db.list_users()}


@app.post("/api/users")
def add_user(body: NewUserBody, user=Depends(require("admin"))):
    name = body.username.strip()
    if not auth.USERNAME_RE.match(name):
        raise HTTPException(400, "Username must be 3-32 characters: letters, digits, . _ -")
    if body.role not in auth.ROLES:
        raise HTTPException(400, "Unknown role.")
    try:
        auth.validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if db.get_user_by_name(name):
        raise HTTPException(400, "That username already exists.")
    db.create_user(name, auth.hash_password(body.password), body.role)
    db.log_event("auth", "USER_CREATED", detail={"actor": user["username"], "new_user": name, "role": body.role})
    return {"ok": True}


@app.post("/api/users/{user_id}/toggle")
def toggle_user(user_id: int, user=Depends(require("admin"))):
    target = db.get_user(user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    if target["id"] == user["id"]:
        raise HTTPException(400, "You cannot disable your own account.")
    db.set_active(user_id, not target["active"])
    db.log_event("auth", "USER_DISABLED" if target["active"] else "USER_ENABLED",
                 detail={"actor": user["username"], "target": target["username"]})
    return {"ok": True}


@app.post("/api/users/{user_id}/password")
def reset_user_password(user_id: int, body: ResetBody, user=Depends(require("admin"))):
    target = db.get_user(user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    try:
        auth.validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.set_password(user_id, auth.hash_password(body.password))
    db.log_event("auth", "PASSWORD_RESET", detail={"actor": user["username"], "target": target["username"]})
    return {"ok": True}


@app.post("/api/demo/run")
def demo_run(user=Depends(current_user)):
    result = build_trace(run_verification, user["username"])
    db.log_event("demo", "COMPLETED", "Automation Demo", detail={"actor": user["username"], "attacks_blocked": result["blocked"]})
    return result

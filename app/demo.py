"""Automated end-to-end walkthrough. Runs the REAL engine in a sandbox app and returns an annotated trace."""
import copy
import hmac as _hmac

from . import database as db
from .security import (create_sample_package, make_envelope, canonical_json, hmac_hex, sha256_bytes,
                       safe_zip_manifest, tamper_package, list_keys, key_exists,
                       MAX_PACKAGE_BYTES, MAX_FILES)

APP = "Automation Demo"
P_PUB, P_VER, P_ATK, P_AUD = "1 · Publisher", "2 · Verifier", "3 · Attack simulations", "4 · Audit & summary"


def build_trace(run_verification, actor="system"):
    db.reset_app(APP)  # sandbox state only
    steps, results = [], []

    def add(phase, title, explain, details=None, outcome="info", status=None):
        steps.append({"n": len(steps) + 1, "phase": phase, "title": title, "explain": explain,
                      "details": details or [], "outcome": outcome, "status": status})

    T = lambda l, v: {"kind": "text", "label": l, "value": str(v)}
    M = lambda l, v: {"kind": "mono", "label": l, "value": str(v)}
    CMP = lambda l, al, a, bl, b: {"kind": "compare", "label": l, "a_label": al, "a": a, "b_label": bl, "b": b, "match": a == b}

    def release(version, hours=0):
        p = create_sample_package(APP, version)
        e, t = make_envelope(p, APP, version, hours)
        return p, {"envelope": e, "hmac": t}

    # ------------------------------------------------ Phase 1: publisher
    pkg = create_sample_package(APP, "1.0.0")
    manifest = safe_zip_manifest(pkg)
    add(P_PUB, "Build the update package",
        "The publisher bundles the application's files into a ZIP archive. Each file is hashed with SHA-256 so any later change to a single byte becomes detectable. Nothing is installed or executed at any point in this demo.",
        [{"kind": "files", "items": [{"name": n, "size": m["size"], "sha": m["sha256"][:24] + "…"} for n, m in manifest.items()]}])
    pkg_sha = sha256_bytes(pkg)
    add(P_PUB, "Fingerprint the whole package",
        "A SHA-256 digest of the complete ZIP is computed. This is a second, independent integrity layer on top of the per-file hashes.",
        [T("Package size", f"{len(pkg)} bytes"), M("Package SHA-256", pkg_sha)])
    env, tag = make_envelope(pkg, APP, "1.0.0", 24)
    envd = {"envelope": env, "hmac": tag}
    add(P_PUB, "Assemble the signed envelope",
        "Metadata is gathered into an envelope: who and what the update is, a unique single-use update ID, an expiry time, the signing key ID, the package fingerprint and the full file manifest.",
        [T("Application / version", f"{env['app_name']} · {env['version']}"), M("Update ID (random, single-use)", env["update_id"]),
         T("Signing key ID", env["key_id"]), T("Expires at", env["expires_at"]), T("Files in manifest", len(env["manifest"]))])
    canon = canonical_json(env)
    add(P_PUB, "Canonicalise the envelope",
        "HMAC works on bytes, so both sides must produce byte-identical input. The envelope is serialised as JSON with sorted keys and no whitespace. Without this step, harmless formatting differences would break verification.",
        [M("Canonical JSON (first 200 chars)", canon.decode()[:200] + "…"), T("Length", f"{len(canon)} bytes"), M("SHA-256 of canonical bytes", sha256_bytes(canon))])
    ring = {k["key_id"]: k for k in list_keys()["keys"]}
    add(P_PUB, "Sign with HMAC-SHA256",
        "The canonical bytes are authenticated with a secret key: tag = HMAC-SHA256(secret, bytes). Only someone holding the secret can produce a valid tag for this exact content. The secret itself is never displayed, only a fingerprint of it.",
        [T("Key ID", env["key_id"]), M("Key fingerprint (sha256 of secret, truncated)", ring[env["key_id"]]["fingerprint"]), M("HMAC-SHA256 tag", tag)], "ok")

    # ------------------------------------------------ Phase 2: verifier (legitimate)
    actual = safe_zip_manifest(pkg)
    add(P_VER, "Receive and inspect the ZIP safely",
        "The verifier treats the upload as hostile. The ZIP is inspected in memory, never extracted to disk, and rejected on any unsafe property.",
        [{"kind": "list", "items": [
            {"text": f"Size {len(pkg)} B within the {MAX_PACKAGE_BYTES // 1048576} MB limit", "ok": True},
            {"text": f"{len(actual)} entries within the {MAX_FILES}-entry limit", "ok": True},
            {"text": "No absolute paths or '..' directory traversal", "ok": True},
            {"text": "No symbolic links", "ok": True}, {"text": "No encrypted entries", "ok": True},
            {"text": "Expanded size within the 100 MB zip-bomb limit", "ok": True}]}])
    expected = hmac_hex(canonical_json(env), env["key_id"])
    add(P_VER, "Recompute and compare the HMAC",
        "The verifier canonicalises the received envelope and computes its own tag using the shared secret, then compares it with the supplied tag using hmac.compare_digest, a constant-time comparison that leaks nothing about where a mismatch occurs.",
        [CMP("Authentication tag", "Recomputed by verifier", expected, "Supplied in envelope", tag),
         T("Comparison method", "hmac.compare_digest (constant time)")], "ok")
    add(P_VER, "Check the signing key is trusted",
        "The envelope names its signing key. It must exist in the local keyring, so old keys keep working after rotation while unknown keys are refused.",
        [T("Claimed key ID", env["key_id"]), T("In keyring", "yes" if key_exists(env["key_id"]) else "no")], "ok")
    add(P_VER, "Compare the package fingerprint",
        "The SHA-256 of the received ZIP is compared with the fingerprint that was covered by the signature.",
        [CMP("Package SHA-256", "Signed fingerprint", env["package_sha256"], "Received package", sha256_bytes(pkg))], "ok")
    add(P_VER, "Verify every file against the manifest",
        "Each file's hash is recomputed and matched against the signed manifest. The check also looks for missing and unexpected files.",
        [{"kind": "files", "items": [{"name": n, "size": m["size"], "sha": m["sha256"][:24] + "…",
                                        "state": "match" if env["manifest"].get(n, {}).get("sha256") == m["sha256"] else "changed"} for n, m in actual.items()]}], "ok")
    add(P_VER, "Check freshness, replay and version",
        "A valid signature does not prove an update is fresh. The verifier also checks the expiry time, whether this update ID was already accepted, and that the version is newer than what is installed.",
        [T("Expires at", env["expires_at"]), T("Update ID seen before", "no"), T("Currently accepted version", "none"), T("Offered version", "1.0.0")], "ok")
    r = run_verification(pkg, envd, accept=True, actor=actor)
    add(P_VER, "Decision: accept the update",
        "All seven checks pass, so the update is accepted and its version and update ID are recorded. That record is what makes the next attacks fail.",
        [{"kind": "checks", "checks": r["checks"]}], "ok" if r["valid"] else "bad", r["status"])

    # ------------------------------------------------ Phase 3: attacks
    def attack(title, explain, pkg_, envd_, pre, accept=False):
        res = run_verification(pkg_, envd_, accept=accept, actor=actor)
        blocked = not res["valid"]
        results.append((title, res["status"], blocked))
        det = pre + [{"kind": "checks", "checks": res["checks"]}, {"kind": "reasons", "items": res["reasons"]}]
        add(P_ATK, title, explain, det, "ok" if blocked else "bad", res["status"])

    p, e = release("1.1.0")
    bad = tamper_package(p)
    bm = safe_zip_manifest(bad)
    changed = next(n for n in bm if bm[n]["sha256"] != e["envelope"]["manifest"][n]["sha256"])
    attack("Attack 1: tamper with a file",
           "An attacker intercepts a correctly signed update and appends malicious bytes to one file. The original envelope is left untouched.",
           bad, e, [T("File modified", changed), CMP("SHA-256 of that file", "Signed manifest", e["envelope"]["manifest"][changed]["sha256"], "Tampered file", bm[changed]["sha256"])])

    p, e = release("1.1.0")
    f = copy.deepcopy(e)
    f["envelope"]["version"] = "9.9.9"
    exp = hmac_hex(canonical_json(f["envelope"]), f["envelope"]["key_id"])
    attack("Attack 2: forge the metadata",
           "The attacker edits the envelope to claim version 9.9.9 but cannot recompute the HMAC without the secret key, so the old tag is reused.",
           p, f, [T("Field changed", "version: 1.1.0 → 9.9.9"), CMP("HMAC tag", "Valid tag for edited content", exp, "Tag the attacker supplies", f["hmac"])])

    attack("Attack 3: replay an accepted update",
           "The legitimate update from Phase 2 is delivered a second time, for example to reinstall a vulnerable build. The signature is still perfectly valid.",
           pkg, envd, [T("Update ID", env["update_id"]), T("Already accepted", "yes (recorded in step 'Decision')")], accept=True)

    p, e = release("0.9.0")
    attack("Attack 4: roll back to an older version",
           "An older release with a genuine signature is pushed to downgrade the app to a version with known vulnerabilities.",
           p, e, [T("Installed version", "1.0.0"), T("Offered version", "0.9.0")], accept=True)

    p, e = release("1.1.0", hours=-1)
    attack("Attack 5: use an expired release",
           "A genuine update is replayed long after its validity window ended. Expiry is part of the signed envelope, so it cannot be edited out.",
           p, e, [T("Expired at", e["envelope"]["expires_at"])])

    p, e = release("1.1.0")
    e["envelope"]["key_id"] = "attacker-key-01"
    attack("Attack 6: claim an unknown signing key",
           "The attacker points the envelope at a key ID of their choosing, hoping the verifier will trust it.",
           p, e, [T("Claimed key ID", "attacker-key-01"), T("In keyring", "no")])

    # ------------------------------------------------ Phase 4: audit & summary
    chain = db.verify_chain()
    add(P_AUD, "Verify the tamper-evident audit log",
        "Every event above was written to a hash-chained log: each row's hash covers the previous row's hash, so editing or deleting history breaks the chain.",
        [T("Entries checked", chain["checked"]), T("Chain intact", "yes" if chain["valid"] else f"NO, broken at #{chain['broken_at']}")], "ok" if chain["valid"] else "bad")
    keys = list_keys()
    add(P_AUD, "Key rotation readiness",
        "Rotation adds a new active key while keeping old ones trusted for verification, so already-published releases stay valid. This demo does not rotate the live key.",
        [T("Keys in keyring", len(keys["keys"])), T("Active key", keys["active"])])
    blocked_n = sum(1 for _, _, b in results if b)
    add(P_AUD, "Summary", f"{blocked_n} of {len(results)} attacks were stopped by the verification engine, and the one legitimate update was accepted.",
        [{"kind": "list", "items": [{"text": f"{t}: {s}", "ok": b} for t, s, b in results]}], "ok" if blocked_n == len(results) else "bad")
    return {"steps": steps, "attacks": len(results), "blocked": blocked_n}

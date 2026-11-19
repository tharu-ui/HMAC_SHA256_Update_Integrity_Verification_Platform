# HMAC Update Integrity Platform (v2.0)

A runnable educational capstone prototype for software-update authenticity and integrity verification.

## What it demonstrates
- HMAC-SHA256 signing and constant-time verification (`hmac.compare_digest`)
- Per-file SHA-256 manifest for ZIP update packages
- Package tampering, missing-file and unexpected-file detection
- Update version / rollback checks
- Replay detection using unique update IDs
- Key rotation (demo keyring)
- Attack simulation controls
- SQLite audit history and downloadable JSON report

> **Important:** This is a local academic prototype, not a production updater. It does not install or execute uploaded software. The demo key is stored in a local `.env` file for convenience. Production systems need protected key storage, authenticated publisher workflows, TLS, access control, key separation, secure boot/update-agent design and operational controls. HMAC uses a shared secret; it is not a public-verification signature scheme.

## What's new in v2.0
- Dark redesigned UI: drag-and-drop uploads, pass-rate chart, release history
- Working key rotation (keyring in `data/keys.json`; old keys stay valid for verification)
- Expiry enforcement and unknown-key detection
- Publish your own ZIP, not just the sample bundle
- One-click Attack Lab: tamper, forged metadata, replay, rollback, expired, unknown key
- Hash & HMAC playground with constant-time tag comparison
- Hash-chained audit log with chain verification, filters, row details and CSV export

## Automated demo (new)
Open **Auto demo** and press start. The server runs the real engine in a sandbox app and the page
plays a 21-step walkthrough on its own: package, fingerprint, envelope, canonicalisation, HMAC signing,
safe ZIP inspection, constant-time tag comparison, manifest check, freshness/replay/version checks,
then six attacks (tamper, forged metadata, replay, rollback, expired, unknown key) and the audit-chain check.
It has pause/resume and Slow / Normal / Fast / Instant speeds. Code: `app/demo.py`.

## Login & roles (new)
On first run an `admin` account is created and its password is **printed once in the terminal**
(or set `ADMIN_PASSWORD` in `.env` beforehand). Forgot it? Run `python reset_admin.py`.

| Role | Can do |
|---|---|
| admin | everything, plus user management and key rotation |
| publisher | publish updates, view keys, hash/HMAC tool |
| verifier | verify updates, attack lab |
| all roles | overview and audit trail |

Security details: PBKDF2-HMAC-SHA256 (600k iterations, per-user salt), server-side sessions
(only a SHA-256 of the token is stored), HttpOnly + SameSite=Strict cookie, 8-hour expiry,
account lockout after 5 failed attempts for 5 minutes, and all sign-ins/user changes appear in the audit trail.

## Requirements
- Python 3.10+
- VS Code
- Internet only for the first installation of Python packages

## Run on Windows (VS Code terminal)
1. Extract the ZIP.
2. Open the extracted `HMAC_Update_Integrity_Platform` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, run:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

5. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
6. Start the application:
   ```powershell
   python run.py
   ```
7. Open the address printed in the terminal (normally `http://127.0.0.1:8000`).

## First demo
1. Go to **Publisher** and create a sample update.
2. Open **Verify** and select the generated ZIP.
3. Verify it. It should pass.
4. In **Attack Lab**, create a tampered copy, then verify that copy.
5. Try replaying the same valid update twice, or test an older version after accepting a newer one.
6. Open **Audit Trail** to review events.

## Project structure
```text
app/
  main.py              FastAPI routes and verification workflow
  security.py          HMAC, manifest, ZIP safety and attack checks
  database.py          SQLite audit and accepted-update records
  static/
    index.html
    styles.css
    app.js
data/                  Generated packages, database and reports
.env                   Local demo secret (created automatically)
run.py
requirements.txt
```

## Security notes
- The ZIP is inspected but never extracted to disk or executed.
- ZIP entries with absolute paths, `..` traversal, encrypted entries or symlinks are rejected.
- The manifest is authenticated together with update metadata.
- A valid HMAC alone does not establish freshness; the platform separately checks version, expiry and replay state.
- The demo uses one local application key. For real deployment, isolate publisher and verifier roles and use a proper secret manager or hardware-backed key storage.

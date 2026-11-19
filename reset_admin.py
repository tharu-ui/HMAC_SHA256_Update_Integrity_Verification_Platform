"""Recover access: python reset_admin.py  (creates or resets the 'admin' account)."""
import getpass
from app import database as db, auth

db.init_db(); db.init_auth_tables()
pw = getpass.getpass("New admin password (min 8 chars): ")
auth.validate_password(pw)
user = db.get_user_by_name("admin")
if user:
    db.set_password(user["id"], auth.hash_password(pw)); db.set_active(user["id"], True)
else:
    db.create_user("admin", auth.hash_password(pw), "admin")
print("Admin account ready.")

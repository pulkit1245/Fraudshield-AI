from app.core.database import session_scope
from sqlalchemy import text
from pprint import pprint

with session_scope() as db:
    sub = db.execute(text("SELECT id, original_filename, status, submitted_at, completed_at FROM apk_submissions ORDER BY submitted_at DESC LIMIT 1")).fetchone()
    if sub:
        print(f"ID: {sub.id}")
        print(f"File: {sub.original_filename}")
        print(f"Status: {sub.status}")
        print(f"Submitted: {sub.submitted_at}")
        print(f"Completed: {sub.completed_at}")
    else:
        print("No submissions found.")

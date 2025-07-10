"""
Database and business logic module for TaskTrackr.

Handles all interactions with SQLite for user and task CRUD, including password hashing.
"""

import sqlite3
from datetime import datetime
from typing import Optional, List
from passlib.context import CryptContext

# CONFIGURATION
import os

DATABASE_URL = os.getenv("SQLITE_DB", "tasktrackr.sqlite")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = sqlite3.connect(DATABASE_URL)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cursor = db.cursor()
    # User table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    # Task table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            due_date TEXT,
            completed INTEGER DEFAULT 0 NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    db.commit()
    db.close()

# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def create_user(email: str, password: str) -> Optional[sqlite3.Row]:
    """Create a user and return the row (omit password hash in response)."""
    db = get_db()
    try:
        password_hash = hash_password(password)
        now_str = datetime.utcnow().isoformat()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, now_str)
        )
        db.commit()
        user_id = cursor.lastrowid
        user = db.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
    except sqlite3.IntegrityError:
        db.close()
        return None
    db.close()
    return user

# PUBLIC_INTERFACE
def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    """Lookup user details by email."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    db.close()
    return user

# PUBLIC_INTERFACE
def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    """Lookup user details by user ID."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    return user

# PUBLIC_INTERFACE
def create_task_for_user(user_id: int, title: str, description: Optional[str], due_date: Optional[datetime], completed: bool) -> sqlite3.Row:
    """Create a new task for a user."""
    db = get_db()
    now_str = datetime.utcnow().isoformat()
    due = due_date.isoformat() if due_date else None
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO tasks (title, description, due_date, completed, user_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (
            title,
            description,
            due,
            int(bool(completed)),
            user_id,
            now_str,
            now_str
        )
    )
    db.commit()
    task_id = cursor.lastrowid
    row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    db.close()
    return row

# PUBLIC_INTERFACE
def get_tasks_for_user(user_id: int) -> List[sqlite3.Row]:
    """Get all tasks for a given user."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM tasks WHERE user_id = ? ORDER BY due_date IS NULL, due_date ASC, created_at DESC",
        (user_id,)
    ).fetchall()
    db.close()
    return rows

# PUBLIC_INTERFACE
def get_task_by_id_for_user(task_id: int, user_id: int) -> Optional[sqlite3.Row]:
    """Get a specific task by ID for a given user."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id)
    ).fetchone()
    db.close()
    return row

# PUBLIC_INTERFACE
def update_task_for_user(task_id: int, user_id: int, title=None, description=None, due_date=None, completed=None) -> Optional[sqlite3.Row]:
    """Update an existing task's fields, only fields provided will be updated."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id)
    ).fetchone()
    if row is None:
        db.close()
        return None
    updated = dict(row)
    if title is not None:
        updated['title'] = title
    if description is not None:
        updated['description'] = description
    if due_date is not None:
        updated['due_date'] = due_date.isoformat() if hasattr(due_date, "isoformat") else due_date
    if completed is not None:
        updated['completed'] = int(bool(completed))
    now_str = datetime.utcnow().isoformat()
    db.execute(
        "UPDATE tasks SET title=?, description=?, due_date=?, completed=?, updated_at=? WHERE id=?",
        (
            updated['title'],
            updated['description'],
            updated['due_date'],
            updated.get('completed', 0),
            now_str,
            task_id
        )
    )
    db.commit()
    row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    db.close()
    return row

# PUBLIC_INTERFACE
def delete_task_for_user(task_id: int, user_id: int) -> bool:
    """Delete a task by ID for the given user."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id)
    ).fetchone()
    if row is None:
        db.close()
        return False
    db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    db.commit()
    db.close()
    return True

# Ensure tables exist on import
init_db()

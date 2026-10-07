import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("keykeep.db")


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                master_password_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site_name TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """)


# Creates a new user in the database
init_db()


def create_user(username, master_password_hash=None):
    with get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO users (username, master_password_hash) VALUES (?, ?)",
            (username, master_password_hash),
        )
        return cursor.lastrowid


# Save a password in the database
def save_credential(user_id, site_name, username, password, notes=None):
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO credentials (user_id, site_name, username, password, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (user_id, site_name, username, password, notes),
        )
        return cursor.lastrowid


# Grabs a single credential from the database
def get_credential(credential_id, user_id=None):
    with get_connection() as connection:
        if user_id is None:
            row = connection.execute(
                "SELECT * FROM credentials WHERE id = ?",
                (credential_id,),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
                (credential_id, user_id),
            ).fetchone()
        return dict(row) if row else None


# Grabs all credentials for a user from the database
def list_credentials(user_id):
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM credentials WHERE user_id = ? ORDER BY site_name ASC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


# Changes a credential in the database
def update_credential(
    credential_id, user_id, site_name=None, username=None, password=None, notes=None
):
    updates = []
    values = []

    if site_name is not None:
        updates.append("site_name = ?")
        values.append(site_name)
    if username is not None:
        updates.append("username = ?")
        values.append(username)
    if password is not None:
        updates.append("password = ?")
        values.append(password)
    if notes is not None:
        updates.append("notes = ?")
        values.append(notes)

    if not updates:
        return False

    updates.append("updated_at = CURRENT_TIMESTAMP")
    values.extend([credential_id, user_id])

    with get_connection() as connection:
        connection.execute(
            f"UPDATE credentials SET {', '.join(updates)} WHERE id = ? AND user_id = ?",
            tuple(values),
        )
        return True


# Deletes a credential from the database
def delete_credential(credential_id, user_id=None):
    with get_connection() as connection:
        if user_id is None:
            cursor = connection.execute(
                "DELETE FROM credentials WHERE id = ?", (credential_id,)
            )
        else:
            cursor = connection.execute(
                "DELETE FROM credentials WHERE id = ? AND user_id = ?",
                (credential_id, user_id),
            )
        return cursor.rowcount > 0

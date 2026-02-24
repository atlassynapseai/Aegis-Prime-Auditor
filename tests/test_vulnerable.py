"""
Test Vulnerable Script - For Aegis Prime Auditor Testing
Contains intentional security vulnerabilities for scanner validation
DO NOT USE IN PRODUCTION
"""

import os
import sqlite3
import hashlib
import pickle

# VULNERABILITY: Hardcoded credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "SuperSecret123!"
API_TOKEN = "sk-1234567890abcdefghijklmnopqrstuvwxyz"


# VULNERABILITY: SQL Injection via f-string
def get_user_by_id(user_id):
    """SQL injection vulnerability using f-string."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # CRITICAL: User input directly in SQL query
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()


# VULNERABILITY: SQL Injection via %-formatting
def get_user_by_name(username):
    """SQL injection vulnerability using %-formatting."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # CRITICAL: User input in formatted SQL
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cursor.fetchall()


# VULNERABILITY: SQL Injection via concatenation
def delete_user(user_id):
    """SQL injection vulnerability using string concatenation."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # CRITICAL: Concatenated SQL query
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()


# VULNERABILITY: Weak cryptographic algorithm (MD5)
def hash_password(password):
    """Using deprecated MD5 for password hashing."""
    # MEDIUM: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: Command injection
def run_user_command(user_input):
    """OS command injection vulnerability."""
    # CRITICAL: User input in system command
    os.system("echo " + user_input)


# VULNERABILITY: Insecure deserialization
def load_session_data(session_bytes):
    """Arbitrary code execution via pickle."""
    # CRITICAL: Unsafe deserialization
    return pickle.loads(session_bytes)


# VULNERABILITY: Path traversal
def read_user_file(filename):
    """Path traversal vulnerability."""
    # HIGH: User-controlled file path
    with open("/app/data/" + filename, 'r') as f:
        return f.read()


if __name__ == "__main__":
    print("Test vulnerable script loaded")
    print(f"AWS Key: {AWS_ACCESS_KEY}")
    print(f"Database Password: {DATABASE_PASSWORD}")

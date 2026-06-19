"""Create or update an admin user. Usage: python scripts/create_admin.py username password"""
import os
import sys

# Add project root directory to sys.path to resolve imports properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash
from init_db import init_master_db, get_master_conn


def create_user(username, password):
    init_master_db()
    conn = get_master_conn()
    c = conn.cursor()
    ph = generate_password_hash(password)
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    if row:
        c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (ph, username))
        print(f'Updated password for user: {username}')
    else:
        import secrets
        c.execute('INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)', (username, ph, secrets.token_hex(16)))
        print(f'Created user: {username}')
    conn.commit()
    conn.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python scripts/create_admin.py <username> <password>')
        sys.exit(1)
    create_user(sys.argv[1], sys.argv[2])

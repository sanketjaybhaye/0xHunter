"""Create or update an admin user. Usage: python create_admin.py username password"""
import os
import sys
from werkzeug.security import generate_password_hash

from init_db import init_db, get_conn

DB_PATH = os.environ.get('DATABASE_PATH', 'database.sqlite')


def create_user(username, password):
    init_db()
    conn = get_conn()
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
        print('Usage: python create_admin.py <username> <password>')
        sys.exit(1)
    create_user(sys.argv[1], sys.argv[2])

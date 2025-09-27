import sqlite3

conn = sqlite3.connect('disk_manager.db')
cur = conn.cursor()

cur.execute('''
CREATE TABLE IF NOT EXISTS remote_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    ssh_key TEXT,
    platform TEXT NOT NULL
)
''')

conn.commit()
conn.close()
print("remote_hosts table ready in disk_manager.db!")


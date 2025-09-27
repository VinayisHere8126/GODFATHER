import sqlite3

conn = sqlite3.connect('disk_manager.db')
cur = conn.cursor()

hosts = [
    ("Server1", "192.168.1.100", "admin", "/path/to/key1.pem", "linux"),
    ("Server2", "192.168.1.101", "root", "/path/to/key2.pem", "linux")
]

cur.executemany('''
INSERT INTO remote_hosts (name, ip, username, ssh_key, platform)
VALUES (?, ?, ?, ?, ?)
''', hosts)

conn.commit()
conn.close()
print("Sample hosts added!")

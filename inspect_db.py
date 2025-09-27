import sqlite3

conn = sqlite3.connect('footy.db')
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

print("Users in database:")
for row in rows:
    print(row)

conn.close()

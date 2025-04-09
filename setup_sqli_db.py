#!/usr/bin/env python3
import sqlite3

# Create or overwrite the demo database
db_path = 'sqli_demo.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Drop and recreate the employees table
cursor.execute('DROP TABLE IF EXISTS employees')
cursor.execute('''
    CREATE TABLE employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        salary INTEGER NOT NULL
    )
''')

# Insert sample employees
employees = [
    ('Alice', 'Manager', 100000),
    ('Bob', 'Engineer', 85000),
    ('Charlie', 'Intern', 30000),
    ('Dave', 'Engineer', 88000),
    ('Eve', 'CTO', 150000)
]
cursor.executemany('INSERT INTO employees (name, role, salary) VALUES (?, ?, ?)', employees)

# Commit and verify
conn.commit()
cursor.execute('SELECT * FROM employees')
rows = cursor.fetchall()

print(f"✅ SQLi demo database created: {db_path}")
print("👥 Sample data inserted:")
print("=" * 40)
for row in rows:
    print(f"ID: {row[0]} | Name: {row[1]} | Role: {row[2]} | Salary: {row[3]}")
print("=" * 40)

conn.close()

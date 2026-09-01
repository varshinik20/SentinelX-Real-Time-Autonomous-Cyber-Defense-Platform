import sqlite3
import pandas as pd
import os

db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "sentinelx.db"))
print(f"Connecting to database: {db_path}\n")

if not os.path.exists(db_path):
    print(f"[!] Database file does not exist at {db_path} yet. Run the backend server first to create it.")
    exit(1)

conn = sqlite3.connect(db_path)

# Adjust pandas display options for clean terminal output
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)

print("=== PERSISTENT DATABASE TABLES ===")
tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table';", conn)
print(tables)
print("\n" + "="*50 + "\n")

for table in tables['name']:
    if table.startswith("sqlite_"):
        continue
    print(f"=== TABLE DATA PREVIEW: {table.upper()} (Showing up to 3 rows) ===")
    df = pd.read_sql_query(f"SELECT * FROM {table} LIMIT 3;", conn)
    if df.empty:
        print("(Table is currently empty)\n")
    else:
        print(df)
        print()

conn.close()

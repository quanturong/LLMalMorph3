import sqlite3, glob, os

# Find newest DB
dbs = sorted(glob.glob('E:/LLMalMorph2/state_prod_*.db'), key=os.path.getmtime, reverse=True)
print("All DBs (newest first):")
for d in dbs[:5]:
    print(f"  {os.path.basename(d)} - {os.path.getsize(d)} bytes")

db = dbs[0]
print(f"\nUsing: {os.path.basename(db)}")
c = sqlite3.connect(db)

tables = c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print(f"Tables: {[t[0] for t in tables]}")

for t in tables:
    count = c.execute(f"SELECT COUNT(*) FROM {t[0]}").fetchone()[0]
    print(f"  {t[0]}: {count} rows")

# Try common table names
for tbl in ['jobs', 'job_state', 'state_transitions', 'artifacts', 'reports']:
    try:
        rows = c.execute(f"SELECT * FROM {tbl} LIMIT 1").fetchall()
        if rows:
            print(f"\n{tbl} sample: {rows[0][:5]}")
    except:
        pass

c.close()

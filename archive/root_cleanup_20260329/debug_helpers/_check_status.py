import sqlite3, sys, json

db = 'state_prod_20260329_004905.db'
con = sqlite3.connect(db)
cur = con.cursor()

# Job states
cur.execute('SELECT sample_id, current_status, last_updated FROM job_states ORDER BY last_updated')
rows = cur.fetchall()
print(f"=== DB: {db} ===")
print("JOBS:")
for r in rows:
    print(f"  {r[0]:20} | {r[1]:25} | {r[2]}")

# Reports
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [t[0] for t in cur.fetchall()]
print(f"\nTables: {tables}")

if 'reports' in tables:
    cur.execute('SELECT sample_id, created_at FROM reports')
    rpts = cur.fetchall()
    print(f"Reports: {rpts}")

# Check error info
cur.execute('SELECT sample_id, current_status, state_json FROM job_states')
for r in cur.fetchall():
    sj = json.loads(r[2]) if r[2] else {}
    eh = sj.get('error_history', [])
    print(f"\n{r[0]} error_history ({len(eh)} entries):", eh[-2:] if eh else 'none')
    # compile result
    cr = sj.get('compile_result')
    if cr:
        print(f"  compile_result: success={cr.get('success')} fix_attempts={cr.get('fix_attempts')}")

con.close()

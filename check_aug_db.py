import sqlite3, json, os, glob
from datetime import datetime

# Find DB
dbs = sorted(glob.glob('project_mutation_output/augmented_batch50_*.db'), key=os.path.getmtime, reverse=True)
db = dbs[0] if dbs else None
print(f"DB: {db}\n")

con = sqlite3.connect(db)

# Status breakdown
rows = con.execute("SELECT current_status, COUNT(*) FROM job_states GROUP BY current_status ORDER BY 2 DESC").fetchall()
total = sum(r[1] for r in rows)
print(f"=== STATUS ({total} total) ===")
for r in rows:
    print(f"  {r[0]}: {r[1]}")
print()

# Most recent updates
print("=== MOST RECENT ACTIVITY ===")
rows = con.execute("SELECT sample_id, current_status, last_updated FROM job_states ORDER BY last_updated DESC LIMIT 10").fetchall()
for r in rows:
    print(f"  {r[1]:<22} {r[0]:<35} {r[2][11:19]}")
print()

# CLOSED details
print("=== CLOSED ===")
rows = con.execute("SELECT sample_id, state_json FROM job_states WHERE current_status=?", ("CLOSED",)).fetchall()
for sid, sj in rows:
    s = json.loads(sj)
    fs = s.get('fix_stats', {})
    print(f"  {sid:<35} build={fs.get('compilation_time_s',0):.0f}s  fixes={fs.get('total_attempts')}")
print()

# BUILD_FAILED details
print("=== BUILD_FAILED ===")
rows = con.execute("SELECT sample_id, state_json FROM job_states WHERE current_status=?", ("BUILD_FAILED",)).fetchall()
for sid, sj in rows:
    s = json.loads(sj)
    fs = s.get('fix_stats', {})
    print(f"  {sid:<35} errors: {fs.get('initial_error_count')} -> {fs.get('final_error_count')}")

con.close()

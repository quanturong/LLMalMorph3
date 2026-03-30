import sqlite3, json, glob, os
dbs = sorted(glob.glob('state_prod_2026032*.db'), key=os.path.getmtime, reverse=True)
for db in dbs[:3]:
    print(f"\n=== {db} (modified: {os.path.getmtime(db):.0f}) ===")
    c = sqlite3.connect(db)
    for r in c.execute('SELECT sample_id, current_status, last_updated FROM job_states ORDER BY last_updated').fetchall():
        print(f"  {r[0]:15} | {r[1]:25} | {r[2]}")
        try:
            sj = json.loads(c.execute('SELECT state_json FROM job_states WHERE sample_id=?', (r[0],)).fetchone()[0])
            print(f"    retries={sj.get('retries',0)} errs={len(sj.get('error_history',[]))}")
        except: pass
    c.close()

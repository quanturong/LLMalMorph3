import sqlite3, json, glob, os, sys

dbs = sorted(glob.glob('E:/LLMalMorph2/state_prod_2026032*.db'), key=os.path.getmtime, reverse=True)
lines = []
for db in dbs[:4]:
    lines.append(f"DB: {os.path.basename(db)} size={os.path.getsize(db)} mod={os.path.getmtime(db):.0f}")
    try:
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        for r in c.execute('SELECT sample_id, current_status, last_updated FROM job_states ORDER BY last_updated').fetchall():
            lines.append(f"  {r[0]:15} | {r[1]:25} | {r[2]}")
        c.close()
    except Exception as e:
        lines.append(f"  ERROR: {e}")

with open('E:/LLMalMorph2/_pipeline_state.txt', 'w') as f:
    f.write('\n'.join(lines))
print("WRITTEN")

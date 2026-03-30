import sqlite3, json
db = 'E:/LLMalMorph2/state_prod_20260329_025713.db'
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
for r in c.execute('SELECT sample_id, current_status, last_updated FROM job_states ORDER BY last_updated').fetchall():
    print(f"{r[0]:15} | {r[1]:25} | {r[2]}")
arts = c.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0]
reps = c.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
print(f"\nArtifacts: {arts}, Reports: {reps}")
c.close()

import sqlite3, glob, os, json

dbs = sorted(glob.glob('E:/LLMalMorph2/state_prod_*.db'), key=os.path.getmtime, reverse=True)
db = dbs[0]

lines = [f'DB: {db}', f'Modified: {os.path.getmtime(db)}']
con = sqlite3.connect(db)
cur = con.cursor()
cur.execute('SELECT sample_id, current_status, last_updated FROM job_states')
for row in cur.fetchall():
    lines.append(f'Job: {row[0]} | {row[1]} | {row[2]}')
cur.execute('SELECT artifact_type, count(*) FROM artifacts GROUP BY artifact_type')
for row in cur.fetchall():
    lines.append(f'Art: {row[0]} = {row[1]}')
con.close()

with open('E:/LLMalMorph2/_pipeline_status.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
print('Done')

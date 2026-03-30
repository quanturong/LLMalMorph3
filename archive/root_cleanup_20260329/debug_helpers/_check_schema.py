import sqlite3, json, os, time

db = 'E:/LLMalMorph2/state_prod_20260328_224931.db'
c = sqlite3.connect(db)
cols = c.execute("PRAGMA table_info(job_states)").fetchall()
print("Columns:", [col[1] for col in cols])
row = c.execute("SELECT * FROM job_states").fetchone()
print("Row:", row)
c.close()

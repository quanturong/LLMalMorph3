import sqlite3, os

dbs = [
    "state_prod_20260328_232400.db",
    "state_prod_20260328_232155.db",
]

for db in dbs:
    c = sqlite3.connect(f"E:/LLMalMorph2/{db}")
    rows = c.execute("SELECT sample_id, current_status FROM job_states ORDER BY created_at").fetchall()
    arts = c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    reps = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    c.close()
    print(f"{db}: jobs={rows} arts={arts} reports={reps}")

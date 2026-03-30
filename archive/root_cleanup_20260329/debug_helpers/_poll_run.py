import sqlite3, json, os, time

db = 'E:/LLMalMorph2/state_prod_20260328_224931.db'
while True:
    c = sqlite3.connect(db)
    row = c.execute("SELECT * FROM job_states").fetchone()
    if row:
        data = json.loads(row[3]) if row[3] else {}
        state = data.get('state', 'unknown')
        transitions = data.get('state_history', [])
        last_t = transitions[-1] if transitions else {}
        arts = c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        reps = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        print(f"State: {state} | Artifacts: {arts} | Reports: {reps} | Last: {last_t.get('to_state','')} at {last_t.get('timestamp','')}")
    c.close()
    
    if state in ('CLOSED', 'FAILED'):
        print("PIPELINE FINISHED!")
        break
    time.sleep(30)

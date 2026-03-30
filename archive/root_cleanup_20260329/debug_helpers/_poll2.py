import sqlite3, json, time

db = 'E:/LLMalMorph2/state_prod_20260328_224931.db'
while True:
    c = sqlite3.connect(db)
    row = c.execute("SELECT current_status, state_json FROM job_states LIMIT 1").fetchone()
    arts = c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    reps = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    c.close()
    
    status = row[0] if row else "N/A"
    state = json.loads(row[1]) if row and row[1] else {}
    trans = state.get("transitions", [])
    last = trans[-1] if trans else {}
    
    print(f"[{time.strftime('%H:%M:%S')}] Status: {status} | Artifacts: {arts} | Reports: {reps} | Transitions: {len(trans)}")
    
    if status in ('CLOSED', 'FAILED'):
        print("=== PIPELINE FINISHED ===")
        for t in trans:
            print(f"  {t['from_state']} -> {t['to_state']} at {t['timestamp']}")
        break
    time.sleep(30)

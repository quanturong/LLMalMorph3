import sqlite3, json, time

db = 'E:/LLMalMorph2/state_prod_20260328_232400.db'
while True:
    c = sqlite3.connect(db)
    rows = c.execute("SELECT sample_id, current_status, state_json FROM job_states ORDER BY created_at").fetchall()
    arts = c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    reps = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    c.close()
    
    statuses = [(r[0], r[1]) for r in rows]
    t = time.strftime('%H:%M:%S')
    status_str = " | ".join(f"{s[0]}={s[1]}" for s in statuses)
    print(f"[{t}] {status_str} | Arts={arts} Reports={reps}")
    
    all_done = all(s[1] in ('CLOSED', 'FAILED') for s in statuses)
    if all_done and len(statuses) == 2:
        print("\n=== ALL JOBS FINISHED ===")
        for r in rows:
            state = json.loads(r[2])
            trans = state.get("transitions", [])
            print(f"\n--- {r[0]} ({r[1]}) ---")
            for t2 in trans:
                print(f"  {t2['from_state']} -> {t2['to_state']}")
        break
    time.sleep(30)

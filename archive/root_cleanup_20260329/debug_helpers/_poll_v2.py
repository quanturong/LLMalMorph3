import sqlite3, glob, os, json, time

db = 'state_prod_20260329_004905.db'

print(f"Polling DB: {db}")
for i in range(20):  # poll 20 times, 30s interval = 10 min max
    time.sleep(30)
    con = sqlite3.connect(db)
    cur = con.cursor()
    cur.execute('SELECT sample_id, current_status FROM job_states')
    jobs = cur.fetchall()
    cur.execute('SELECT artifact_type, count(*) FROM artifacts GROUP BY artifact_type')
    arts = cur.fetchall()
    cur.execute('SELECT count(*) FROM reports')
    rpts = cur.fetchone()[0]
    con.close()
    
    statuses = {j[0]: j[1] for j in jobs}
    art_count = {a[0]: a[1] for a in arts}
    
    print(f"[{i+1}] {statuses} | arts={art_count} | reports={rpts}")
    
    # Check if both done
    all_done = all(s in ('CLOSED', 'FAILED') for s in statuses.values())
    if all_done:
        print("Both jobs completed!")
        # Print reports
        con = sqlite3.connect(db)
        cur = con.cursor()
        cur.execute('SELECT sample_id, threat_score, risk_level, report_path, created_at FROM reports')
        for row in cur.fetchall():
            print(f"  REPORT: {row}")
        con.close()
        break

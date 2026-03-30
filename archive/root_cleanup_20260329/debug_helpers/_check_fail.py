import sqlite3, json

db = 'state_prod_20260329_001453.db'
con = sqlite3.connect(db)

print(f'=== DB: {db} ===\n')

# Get job states with error info
cur = con.cursor()
cur.execute('SELECT sample_id, current_status, state_json FROM job_states')
for row in cur.fetchall():
    sid, status, state_json = row
    state = json.loads(state_json)
    print(f'Job: {sid} | Status: {status}')
    
    # Show error history
    err_hist = state.get('error_history', [])
    if err_hist:
        print(f'  Error history ({len(err_hist)} entries):')
        for eh in err_hist[-3:]:  # last 3
            print(f'    [{eh.get("timestamp","")}] {eh.get("error_message","")[:200]}')
    
    # Show transitions  
    transitions = state.get('transitions', [])
    if transitions:
        print(f'  Last transitions:')
        for t in transitions[-3:]:
            print(f'    {t.get("from_status","")} -> {t.get("to_status","")} ({t.get("reason","")})')
    print()

# Artifacts
print('=== ARTIFACTS ===')
cur.execute('SELECT sample_id, artifact_type, file_path, size_bytes FROM artifacts ORDER BY created_at')
for row in cur.fetchall():
    sid, atype, fpath, size = row
    print(f'  [{sid}] {atype}: {size}b')

con.close()

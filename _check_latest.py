import sqlite3, glob, json
dbs = sorted(glob.glob(r"E:\LLMalMorph2\project_mutation_output\smoke_*.db"))
if not dbs:
    print("No DB found")
    exit()

db = dbs[-1]
c = sqlite3.connect(db)
row = c.execute("SELECT sample_id, current_status, last_updated, state_json FROM job_states ORDER BY rowid DESC LIMIT 1").fetchone()
if row:
    sample, status, updated, state_json = row
    print(f"Sample: {sample}")
    print(f"Status: {status}")
    print(f"Updated: {updated}")
    
    # Parse state JSON to show report status if available
    if state_json:
        state = json.loads(state_json)
        if state.get('report_id'):
            print(f"Report ID: {state['report_id']}")
        if state.get('analysis_result_id'):
            print(f"Analysis Result ID: {state['analysis_result_id']}")
c.close()

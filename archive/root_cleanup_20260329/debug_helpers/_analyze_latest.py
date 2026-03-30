import sqlite3, json

db = 'E:/LLMalMorph2/state_prod_20260329_013837.db'
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)

for r in c.execute('SELECT sample_id, current_status, state_json FROM job_states').fetchall():
    sj = json.loads(r[2])
    print(f"\n=== {r[0]} | {r[1]} ===")
    eh = sj.get('error_history', [])
    print(f"  error_history ({len(eh)} entries):")
    for e in eh[-3:]:
        print(f"    {str(e)[:200]}")
    cr = sj.get('compile_result')
    if cr:
        print(f"  compile: success={cr.get('success')} fix_attempts={cr.get('fix_attempts')}")
    # Check all keys
    for k in ['exe_path', 'sandbox_task_id', 'sandbox_report', 'threat_score']:
        if k in sj and sj[k]:
            print(f"  {k}: {str(sj[k])[:100]}")

# Artifacts
print("\n=== ARTIFACTS ===")
for r in c.execute('SELECT artifact_type, file_path FROM artifacts ORDER BY created_at').fetchall():
    print(f"  {r[0]:30} | {r[1]}")

# Reports
print("\n=== REPORTS ===")
for r in c.execute('SELECT sample_id, report_path, summary_path FROM reports').fetchall():
    print(f"  {r[0]:15} | {r[1]}")

c.close()

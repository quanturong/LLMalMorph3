import sqlite3, json, os

db = 'E:/LLMalMorph2/state_prod_20260329_025713.db'
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)

print("=" * 70)
print("PIPELINE RESULTS: POSGrabber + Prosto_Stealer")
print("=" * 70)

# Job details
for r in c.execute('SELECT sample_id, current_status, state_json, last_updated FROM job_states ORDER BY last_updated').fetchall():
    sj = json.loads(r[2])
    print(f"\n{'=' * 50}")
    print(f"SAMPLE: {r[0]}")
    print(f"STATUS: {r[1]}")
    print(f"UPDATED: {r[3]}")
    print(f"Retries: {sj.get('retries', 0)}")
    print(f"Sandbox retries: {sj.get('sandbox_retries', 0)}")
    eh = sj.get('error_history', [])
    print(f"Errors: {len(eh)}")
    for e in eh:
        print(f"  - {e.get('error_code','?')}: {str(e.get('error_message',''))[:150]}")
    if sj.get('exe_path'):
        print(f"EXE: {sj['exe_path']}")
    if sj.get('sandbox_task_id'):
        print(f"Sandbox task: {sj['sandbox_task_id']}")

# Artifacts
print(f"\n{'=' * 50}")
print("ARTIFACTS:")
for r in c.execute('SELECT artifact_type, file_path, size_bytes FROM artifacts ORDER BY created_at').fetchall():
    fname = os.path.basename(r[1]) if r[1] else "?"
    print(f"  {r[0]:30} | {fname:50} | {r[2] or '?'}B")

# Reports
print(f"\n{'=' * 50}")
print("REPORTS:")
for r in c.execute('SELECT sample_id, report_path, summary_path FROM reports').fetchall():
    print(f"  {r[0]:15}")
    if r[1] and os.path.exists(r[1]):
        with open(r[1]) as f:
            rpt = json.load(f)
        print(f"    Threat Score: {rpt.get('threat_score', '?')}/10")
        print(f"    Risk Level: {rpt.get('risk_level', '?')}")
        print(f"    Detection Count: {rpt.get('detection_count', '?')}")
        print(f"    Primary Category: {rpt.get('primary_category', '?')}")
        
        # Behaviors
        behaviors = rpt.get('key_behaviors', [])
        if behaviors:
            print(f"    Key Behaviors ({len(behaviors)}):")
            for b in behaviors[:5]:
                print(f"      - {b}")
        
        # IOCs
        iocs = rpt.get('iocs', [])
        if iocs:
            print(f"    IOCs ({len(iocs)}):")
            for ioc in iocs[:5]:
                print(f"      - [{ioc.get('type','')}] {ioc.get('value','')[:80]}")
        
        # Timings  
        timing = rpt.get('timing', {})
        if timing:
            print(f"    Total time: {timing.get('total_time_s', '?')}s")
            print(f"    Build time: {timing.get('build_time_s', '?')}s")
            print(f"    Sandbox time: {timing.get('sandbox_time_s', '?')}s")
    else:
        print(f"    Report file: {r[1]}")

c.close()

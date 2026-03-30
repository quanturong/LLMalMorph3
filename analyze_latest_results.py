import sqlite3
import json
import glob
import os
from datetime import datetime

# Find the latest state DB
dbs = sorted(glob.glob("state_prod_*.db"), key=os.path.getmtime, reverse=True)
latest_db = dbs[0]
print(f"=== PHÂN TÍCH KẾT QUẢ MULTI-AGENT PIPELINE ===")
print(f"Database: {latest_db}")
print(f"Modified: {datetime.fromtimestamp(os.path.getmtime(latest_db))}")
print()

conn = sqlite3.connect(latest_db)
cursor = conn.cursor()

# Get all job states
cursor.execute('SELECT * FROM job_states ORDER BY created_at DESC')
jobs = cursor.fetchall()

print(f"Tổng số job: {len(jobs)}")
print()

for i, job in enumerate(jobs):
    job_id, sample_id, status, metadata_str, created_at, last_updated = job
    metadata = json.loads(metadata_str)
    
    print(f"{'='*80}")
    print(f"JOB {i+1}: {sample_id}")
    print(f"  Status: {status}")
    print(f"  Project: {metadata.get('project_name', 'N/A')}")
    print(f"  Language: {metadata.get('language', 'N/A')}")
    print(f"  Strategies: {metadata.get('requested_strategies', [])}")
    print(f"  Created: {created_at}")
    print(f"  Updated: {last_updated}")
    print(f"  Retries: general={metadata.get('retry_count',0)}, build={metadata.get('build_retry_count',0)}, llm={metadata.get('llm_retry_count',0)}")
    
    # Timeline
    transitions = metadata.get('transitions', [])
    print(f"\n  TIMELINE ({len(transitions)} transitions):")
    prev_ts = None
    for t in transitions:
        ts = t['timestamp']
        duration = ""
        if prev_ts:
            try:
                t1 = datetime.fromisoformat(prev_ts)
                t2 = datetime.fromisoformat(ts)
                delta = (t2 - t1).total_seconds()
                if delta >= 60:
                    duration = f" [{delta/60:.1f} min]"
                elif delta >= 1:
                    duration = f" [{delta:.1f}s]"
                else:
                    duration = f" [{delta*1000:.0f}ms]"
            except:
                pass
        print(f"    {t['from_state']:25s} → {t['to_state']:25s}{duration}")
        prev_ts = ts
    
    # Errors
    errors = metadata.get('error_history', [])
    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for e in errors:
            print(f"    • {e.get('agent','?')}: {e.get('error_message','?')[:100]}")
    else:
        print(f"\n  NO ERRORS!")
    
    # Artifacts
    print(f"\n  ARTIFACTS:")
    for key in ['source_artifact_id', 'mutation_artifact_id', 'variant_artifact_id', 'compiled_artifact_id']:
        val = metadata.get(key)
        if val:
            print(f"    {key}: {val}")

# Reports
cursor.execute('SELECT * FROM reports')
reports = cursor.fetchall()
print(f"\n{'='*80}")
print(f"REPORTS ({len(reports)}):")
for r in reports:
    print(f"  Report ID: {r[0]}")
    print(f"  Job ID: {r[1]}")
    print(f"  Sample ID: {r[2]}")
    print(f"  Report Path: {r[3]}")
    print(f"  Summary Path: {r[4]}")
    print(f"  Created: {r[5]}")
    
    # Read report if exists
    if os.path.exists(r[3]):
        with open(r[3], 'r') as f:
            report_data = json.load(f)
        print(f"\n  REPORT CONTENT:")
        for key in ['job_id', 'sample_id', 'project_name', 'final_status', 'total_phases_completed']:
            if key in report_data:
                print(f"    {key}: {report_data[key]}")
        phases = report_data.get('phases', {})
        if phases:
            print(f"    Phases:")
            for phase_name, phase_data in phases.items():
                status = phase_data.get('status', 'N/A')
                duration = phase_data.get('duration_s', 'N/A')
                print(f"      {phase_name}: {status} ({duration}s)")
    
    if r[4] and os.path.exists(r[4]):
        with open(r[4], 'r') as f:
            summary = json.load(f)
        print(f"\n  EXECUTIVE SUMMARY:")
        for key, val in summary.items():
            if isinstance(val, str) and len(val) < 200:
                print(f"    {key}: {val}")
            elif isinstance(val, list):
                print(f"    {key}: {val[:3]}")

# Artifacts table
cursor.execute('SELECT artifact_id, artifact_type, sha256, size_bytes, created_at FROM artifacts')
artifacts = cursor.fetchall()
print(f"\n{'='*80}")
print(f"ALL ARTIFACTS ({len(artifacts)}):")
for a in artifacts:
    size_kb = a[3] / 1024 if a[3] else 0
    print(f"  [{a[1]:20s}] {a[0][:12]}... size={size_kb:.1f}KB created={a[4]}")

conn.close()
print(f"\n{'='*80}")
print("Analysis complete!")

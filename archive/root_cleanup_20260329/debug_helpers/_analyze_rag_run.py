import sqlite3, json, os, glob
from datetime import datetime

db = 'E:/LLMalMorph2/state_prod_20260328_224931.db'
c = sqlite3.connect(db)

# Get job state
row = c.execute("SELECT current_status, state_json FROM job_states LIMIT 1").fetchone()
state = json.loads(row[1])
transitions = state.get("transitions", [])

print("=" * 60)
print("  PIPELINE ANALYSIS: RAG + Surgical Fix Run")
print("=" * 60)
print(f"Status: {row[0]}")
print(f"Job ID: {state['job_id']}")
print(f"Sample: {state['sample_id']}")
print(f"Transitions: {len(transitions)}")
print(f"Errors: {len(state.get('error_history', []))}")

# Timing
print("\n--- Phase Timing ---")
for i in range(len(transitions) - 1):
    t1 = datetime.fromisoformat(transitions[i]['timestamp'])
    t2 = datetime.fromisoformat(transitions[i+1]['timestamp'])
    delta = (t2 - t1).total_seconds()
    if delta > 0.5:  # Only show meaningful durations
        print(f"  {transitions[i]['to_state']:25s} -> {transitions[i+1]['to_state']:25s} : {delta:8.1f}s")

# Total time
t_start = datetime.fromisoformat(transitions[0]['timestamp'])
t_end = datetime.fromisoformat(transitions[-1]['timestamp'])
total = (t_end - t_start).total_seconds()
print(f"\n  TOTAL: {total:.1f}s ({total/60:.1f} min)")

# Artifacts
print("\n--- Artifacts ---")
arts = c.execute("SELECT artifact_type, file_path, size_bytes FROM artifacts ORDER BY created_at").fetchall()
for a in arts:
    size_kb = (a[2] or 0) / 1024
    print(f"  {a[0]:30s} : {size_kb:8.1f} KB")

# Read behavior analysis
print("\n--- Behavior Analysis ---")
for a in arts:
    if a[0] == 'behavior_analysis_result' and a[1] and os.path.exists(a[1]):
        with open(a[1]) as f:
            ba = json.load(f)
        print(f"  Threat Score: {ba.get('threat_score', 'N/A')}/10")
        print(f"  Detection Count: {ba.get('detection_count', 'N/A')}")
        print(f"  Primary Category: {ba.get('primary_category', 'N/A')}")
        print(f"  Category Confidence: {ba.get('category_confidence', 'N/A')}")
        print(f"  Analysis Method: {ba.get('analysis_method', 'N/A')}")
        print(f"  Analysis Duration: {ba.get('analysis_duration_s', 'N/A'):.1f}s")
        print(f"  IOCs: {len(ba.get('iocs', []))}")
        print(f"  Key Behaviors:")
        for b in ba.get('key_behaviors', []):
            print(f"    - {b}")
        print(f"  Anomalies:")
        for an in ba.get('anomalies', []):
            print(f"    - {an}")
        print(f"\n  Analyst Narrative:\n    {ba.get('analyst_narrative', 'N/A')[:500]}")

# Read decision
print("\n--- Decision ---")
for a in arts:
    if a[0] == 'decision_result' and a[1] and os.path.exists(a[1]):
        with open(a[1]) as f:
            dec = json.load(f)
        print(f"  Action: {dec.get('action', 'N/A')}")
        print(f"  Rationale: {dec.get('rationale', 'N/A')}")
        print(f"  Confidence: {dec.get('confidence', 'N/A')}")
        print(f"  Source: {dec.get('source', 'N/A')}")
        llm_raw = dec.get('llm_raw_output', {})
        if llm_raw:
            print(f"  LLM Recommended: {llm_raw.get('recommended_action', 'N/A')}")
            print(f"  LLM Rationale: {llm_raw.get('rationale', 'N/A')[:300]}")

# Report
print("\n--- Report ---")
reps = c.execute("SELECT * FROM reports LIMIT 1").fetchone()
if reps:
    print(f"  Report ID: {reps[0][:16]}...")
    if reps[4] and os.path.exists(reps[4]):
        with open(reps[4]) as f:
            rep = json.load(f)
        summary = rep.get('executive_summary', {})
        print(f"  Risk Level: {summary.get('risk_level', 'N/A')}")
        print(f"  Key Findings: {len(summary.get('key_findings', []))}")
        for kf in summary.get('key_findings', []):
            print(f"    - {kf}")

# Compare with previous run
print("\n" + "=" * 60)
print("  COMPARISON: Previous (Mahoraga) vs Current (RAG+Surgical)")
print("=" * 60)

prev_db = 'E:/LLMalMorph2/state_prod_20260328_215508.db'
if os.path.exists(prev_db):
    pc = sqlite3.connect(prev_db)
    prev_row = pc.execute("SELECT current_status, state_json FROM job_states LIMIT 1").fetchone()
    prev_state = json.loads(prev_row[1])
    prev_trans = prev_state.get("transitions", [])
    pt_start = datetime.fromisoformat(prev_trans[0]['timestamp'])
    pt_end = datetime.fromisoformat(prev_trans[-1]['timestamp'])
    prev_total = (pt_end - pt_start).total_seconds()
    
    # Get build timing for both
    for trans_list, label in [(transitions, "Current (RAG+Surgical)"), (prev_trans, "Previous (Mahoraga)")]:
        for i in range(len(trans_list)):
            if trans_list[i].get('to_state') == 'BUILD_VALIDATING':
                for j in range(i+1, len(trans_list)):
                    if trans_list[j].get('to_state') in ('BUILD_READY', 'BUILD_FAILED'):
                        bt1 = datetime.fromisoformat(trans_list[i]['timestamp'])
                        bt2 = datetime.fromisoformat(trans_list[j]['timestamp'])
                        build_time = (bt2 - bt1).total_seconds()
                        print(f"  {label:35s}: Build={build_time:.1f}s Total={prev_total if 'Prev' in label else total:.1f}s")
                        break
                break
    
    pc.close()

c.close()
print("\nDone!")

import sqlite3
import json
from datetime import datetime

print("=== PHÂN TÍCH KẾT QUẢ MULTI-AGENT PIPELINE GẦN NHẤT ===\n")

# Connect to the state database
conn = sqlite3.connect('E:\\LLMalMorph2\\state_prod_20260328_183800.db')
cursor = conn.cursor()

# Get all job states
cursor.execute('SELECT * FROM job_states ORDER BY created_at DESC')
jobs = cursor.fetchall()

print(f"📊 Tổng số job đã chạy: {len(jobs)}")
print("\n🕐 Các job gần đây:")

for i, job in enumerate(jobs[:5]):
    job_id, sample_id, status, metadata_str, created_at, last_updated = job
    metadata = json.loads(metadata_str)
    
    print(f"\n{i+1}. 🎯 Job: {sample_id}")
    print(f"   📍 Status: {status}")
    print(f"   📅 Thời gian: {created_at} → {last_updated}")
    print(f"   🔧 Project: {metadata.get('project_name', 'N/A')}, Language: {metadata.get('language', 'N/A')}")
    
    if status == 'FAILED':
        error_history = metadata.get('error_history', [])
        if error_history:
            latest_error = error_history[-1]
            print(f"   ❌ Lỗi: {latest_error.get('error_message', 'Unknown error')}")
    
    # Get mutation statistics if available
    mutation_artifact_id = metadata.get('mutation_artifact_id')
    if mutation_artifact_id:
        cursor.execute('SELECT * FROM artifacts WHERE artifact_id = ?', (mutation_artifact_id,))
        mutation_artifact = cursor.fetchone()
        if mutation_artifact:
            try:
                with open(mutation_artifact[4], 'r') as f:
                    mutation_data = json.load(f)
                    stats = mutation_data.get('statistics', {})
                    if stats:
                        print(f"   📈 Mutations: {stats.get('total_mutated', 0)}/{stats.get('total_selected', 0)} "
                              f"(Success rate: {stats.get('success_rate', 0):.1f}%)")
            except:
                pass

print("\n" + "="*80)

# Analyze the most recent job in detail
if jobs:
    latest_job = jobs[0]
    job_id, sample_id, status, metadata_str, created_at, last_updated = latest_job
    metadata = json.loads(metadata_str)
    
    print(f"\n🔍 PHÂN TÍCH CHI TIẾT JOB GẦN NHẤT: {sample_id}")
    print(f"📊 Job ID: {job_id}")
    print(f"🎯 Project: {metadata.get('project_name', 'N/A')}")
    print(f"💻 Language: {metadata.get('language', 'N/A')}")
    print(f"⚡ Strategies: {metadata.get('requested_strategies', [])}")
    print(f"📈 Status: {status}")
    
    # Timeline analysis
    transitions = metadata.get('transitions', [])
    print(f"\n📅 TIMELINE:")
    for transition in transitions:
        from_state = transition['from_state']
        to_state = transition['to_state']
        timestamp = transition['timestamp']
        print(f"   {from_state} → {to_state} ({timestamp})")
    
    # Error analysis
    error_history = metadata.get('error_history', [])
    if error_history:
        print(f"\n❌ LỊCH SỬ LỖI:")
        for error in error_history:
            print(f"   • {error.get('agent', 'Unknown')}: {error.get('error_message', 'Unknown')}")
            print(f"     Code: {error.get('error_code', 'N/A')}, Retryable: {error.get('is_retryable', 'N/A')}")
    
    # Retry analysis
    print(f"\n🔄 SỐ LẦN RETRY:")
    print(f"   • General: {metadata.get('retry_count', 0)}")
    print(f"   • Build: {metadata.get('build_retry_count', 0)}")
    print(f"   • LLM: {metadata.get('llm_retry_count', 0)}")
    print(f"   • Sandbox: {metadata.get('sandbox_retry_count', 0)}")

conn.close()

print("\n" + "="*80)
print("✅ Phân tích complete!")
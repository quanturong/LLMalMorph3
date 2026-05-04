#!/usr/bin/env python3
import requests
import json
import time

# Load API key
with open('.env', 'r', encoding='utf-8') as f:
    for line in f:
        if 'VIRUSTOTAL_API_KEY' in line:
            vt_key = line.split('=')[1].strip()
            break

variant_exe = r'e:\LLMalMorph2\project_mutation_output\test_prosto_strat5_20260412_224723\artifacts\14\1476ab52d70c0aa6ef501eeb21848bd758ac343cc54915ee1752ee98a1eb36a0\prosto_stealer_source_code_08580ec0.exe'
original_exe = r'e:\LLMalMorph2\project_mutation_output\test_prosto_strat5_20260412_224723\artifacts\fb\fb41e4aeb36234e5d21b03b411562d350add6fe4caba444d80b898c6a4e29237\prosto_stealer_source_code_orig_08580ec0.exe'

print('[VARIANT] Submitting to VirusTotal...')
with open(variant_exe, 'rb') as f:
    files = {'file': f}
    headers = {'x-apikey': vt_key}
    r = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
    variant_result = r.json()
    print(json.dumps(variant_result, indent=2))
    variant_analysis_id = variant_result.get('data', {}).get('id', '')
    print(f'>>> Variant analysis ID: {variant_analysis_id}')

print('\n[ORIGINAL] Submitting to VirusTotal...')
with open(original_exe, 'rb') as f:
    files = {'file': f}
    headers = {'x-apikey': vt_key}
    r = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
    original_result = r.json()
    print(json.dumps(original_result, indent=2))
    original_analysis_id = original_result.get('data', {}).get('id', '')
    print(f'>>> Original analysis ID: {original_analysis_id}')

# Wait 10 seconds before checking results
print('\n[WAIT] Sleeping 10 seconds for VT analysis...')
time.sleep(10)

print('\n[RESULTS] Fetching variant analysis...')
r = requests.get(f'https://www.virustotal.com/api/v3/analyses/{variant_analysis_id}', 
                 headers={'x-apikey': vt_key})
variant_analysis = r.json()
print(json.dumps(variant_analysis, indent=2))

print('\n[RESULTS] Fetching original analysis...')
r = requests.get(f'https://www.virustotal.com/api/v3/analyses/{original_analysis_id}', 
                 headers={'x-apikey': vt_key})
original_analysis = r.json()
print(json.dumps(original_analysis, indent=2))

# Extract malicious count
variant_stats = variant_analysis.get('data', {}).get('attributes', {}).get('stats', {})
original_stats = original_analysis.get('data', {}).get('attributes', {}).get('stats', {})

variant_malicious = variant_stats.get('malicious', 0)
original_malicious = original_stats.get('malicious', 0)

print('\n' + '='*60)
print('STRAT5 VIRUSTOTAL RESULTS')
print('='*60)
print(f'Variant:  {variant_malicious} engines detected as malicious')
print(f'Original: {original_malicious} engines detected as malicious')
print(f'Delta:    {variant_malicious - original_malicious} (negative = evasion success)')
print('='*60)

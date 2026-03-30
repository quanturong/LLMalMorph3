import sqlite3, json, os

db = 'state_prod_20260328_232155.db'  # The successful pos_prod run
con = sqlite3.connect(db)

cur = con.cursor()
cur.execute("SELECT artifact_id, sample_id, file_path FROM artifacts WHERE artifact_type='source_parse_result'")
rows = cur.fetchall()

for art_id, sample_id, fpath in rows:
    print(f'\n=== {sample_id} source_parse_result ===')
    if fpath and os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        project = data.get('raw_project', {})
        print(f'  project_name: {data.get("project_name")}')
        print(f'  build_system: {project.get("build_system")}')
        print(f'  compiler: {project.get("compiler")}')
        print(f'  root_dir: {project.get("root_dir")}')
        print(f'  compile_command: {str(project.get("compile_command",""))[:300]}')
        print(f'  source_files count: {len(data.get("source_files", []))}')
        print(f'  functions count: {len(data.get("functions", []))}')
    else:
        print(f'  File not found: {fpath}')

# Also check variant
cur.execute("SELECT artifact_id, sample_id, file_path, size_bytes FROM artifacts WHERE artifact_type='variant_source'")
for art_id, sample_id, fpath, size in cur.fetchall():
    print(f'\n=== {sample_id} variant_source ({size}b) ===')
    if fpath and os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        proj = data.get('raw_project', {})
        print(f'  build_system: {proj.get("build_system")}')
        print(f'  compiler: {proj.get("compiler")}')
        print(f'  compile_command: {str(proj.get("compile_command",""))[:300]}')

con.close()

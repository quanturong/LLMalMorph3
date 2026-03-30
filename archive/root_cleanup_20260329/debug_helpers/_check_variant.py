import sqlite3, json, os

db = 'state_prod_20260329_001453.db'
con = sqlite3.connect(db)

# Get source_parse artifacts
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
        print(f'  source_files count: {len(data.get("source_files", []))}')
        print(f'  functions count: {len(data.get("functions", []))}')
        # Check variant_source too
    else:
        print(f'  File not found: {fpath}')

# Get variant_source to see what build system
cur.execute("SELECT artifact_id, sample_id, file_path, size_bytes FROM artifacts WHERE artifact_type='variant_source'")
for art_id, sample_id, fpath, size in cur.fetchall():
    print(f'\n=== {sample_id} variant_source ({size}b) ===')
    if fpath and os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        proj = data.get('raw_project', {})
        print(f'  build_system: {proj.get("build_system")}')
        print(f'  compiler: {proj.get("compiler")}')
        print(f'  compile_command: {str(proj.get("compile_command", ""))[:200]}')
        # Show some files
        files = data.get('source_files', [])
        print(f'  source_files: {files[:3]}')
    else:
        print(f'  Not found: {fpath}')

con.close()

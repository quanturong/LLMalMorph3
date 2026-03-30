import sqlite3, json, os

db = 'state_prod_20260329_001453.db'
con = sqlite3.connect(db)
cur = con.cursor()

# Get variant_source artifacts
cur.execute("SELECT artifact_id, sample_id, file_path, size_bytes FROM artifacts WHERE artifact_type='variant_source'")
for art_id, sample_id, fpath, size in cur.fetchall():
    print(f'\n=== {sample_id} variant_source ({size}b) ===')
    if fpath and os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        # Print top-level keys
        keys = list(data.keys())
        print(f'  Keys: {keys}')
        for k in keys:
            v = data[k]
            if isinstance(v, str):
                print(f'  {k}: {v[:100]}')
            elif isinstance(v, list):
                print(f'  {k}: list[{len(v)}] = {str(v[:2])[:100]}')
            elif isinstance(v, dict):
                print(f'  {k}: dict keys={list(v.keys())}')
            else:
                print(f'  {k}: {type(v).__name__} = {str(v)[:50]}')
    else:
        print(f'  Not found: {fpath}')

con.close()

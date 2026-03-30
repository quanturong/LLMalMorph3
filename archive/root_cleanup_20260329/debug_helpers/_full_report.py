import sqlite3, json, os, glob

db = 'E:/LLMalMorph2/state_prod_20260329_025713.db'
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)

for r in c.execute('SELECT sample_id, report_path, summary_path FROM reports').fetchall():
    print(f"\n=== {r[0]} ===")
    # Read report
    if r[1] and os.path.exists(r[1]):
        with open(r[1]) as f:
            rpt = json.load(f)
        # Print ALL top-level keys and values
        for k, v in rpt.items():
            if isinstance(v, (str, int, float, bool, type(None))):
                print(f"  {k}: {v}")
            elif isinstance(v, list):
                print(f"  {k}: [{len(v)} items]")
                for item in v[:3]:
                    print(f"    - {str(item)[:120]}")
            elif isinstance(v, dict):
                print(f"  {k}: {{keys={list(v.keys())[:10]}}}")
    
    # Read summary
    if r[2] and os.path.exists(r[2]):
        print(f"\n  --- Summary ---")
        with open(r[2]) as f:
            smr = json.load(f)
        for k, v in smr.items():
            if isinstance(v, (str, int, float, bool, type(None))):
                print(f"  {k}: {v}")

c.close()

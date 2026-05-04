import requests, json, time, os

VT_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")
ORIG    = r"project_mutation_output\prosto_strat1_20260504_073249\work\orig_build_48178ce5\variant_build_48178ce5_orig_48178ce5.exe"
VARIANT = r"project_mutation_output\prosto_strat1_20260504_073249\work\build_48178ce5\variant_build_48178ce5_48178ce5.exe"
HDR     = {"x-apikey": VT_KEY}

ids = {}
for label, path in [("original", ORIG), ("variant", VARIANT)]:
    with open(path, "rb") as f:
        r = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=HDR,
            files={"file": (label + ".exe", f)},
        )
    data = r.json()
    aid  = data.get("data", {}).get("id", "")
    ids[label] = aid
    print(f"[{label.upper()}] submitted  analysis_id: {aid}")

print("\nWaiting 60s for VT analysis...")
time.sleep(60)

print()
for label, aid in ids.items():
    r     = requests.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=HDR)
    a     = r.json()
    attrs = a.get("data", {}).get("attributes", {})
    stats  = attrs.get("stats", {})
    status = attrs.get("status", "?")
    mal    = stats.get("malicious", 0)
    sus    = stats.get("suspicious", 0)
    und    = stats.get("undetected", 0)
    total  = sum(stats.values())
    sha    = a.get("meta", {}).get("file_info", {}).get("sha256", "")
    print(f"[{label.upper()}]  status={status}  malicious={mal}/{total}  suspicious={sus}  undetected={und}")
    if sha:
        print(f"  https://www.virustotal.com/gui/file/{sha}")

print()
# Check if still queued — remind user to re-poll
for label, aid in ids.items():
    print(f"  Re-poll {label}: https://www.virustotal.com/gui/analysis/{aid}")

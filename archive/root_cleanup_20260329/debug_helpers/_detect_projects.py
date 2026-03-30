import sys
sys.path.insert(0, 'src')
from project_detector import ProjectDetector

paths = [
    "samples/experiment_samples/extracted/samples/experiment_samples/Prosto_Stealer/prosto_stealer_source_code",
    "samples/experiment_samples/extracted/samples/experiment_samples/Hidden_VNC_BOT/hiddenvnc_code_files",
    "samples/experiment_samples/extracted/samples/experiment_samples/trojan_posgrabber/Trojan-Banker.Win32.Dexter_EXPERIMENT/Dexter/POSGrabber",
]

for path in paths:
    print(f"\nPath: {path}")
    try:
        det = ProjectDetector(path)
        projs = det.detect_projects(recursive=True)
        if projs:
            for p in projs:
                print(f"  Project: name={p.name!r} lang={getattr(p,'language','?')} type={getattr(p,'project_type','?')}")
        else:
            print("  No projects detected")
    except Exception as e:
        print(f"  ERROR: {e}")

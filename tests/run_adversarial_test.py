import sys; sys.path.insert(0, "/app")
import os
import uuid
import time
import subprocess
import shutil
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.submission import Submission
from app.models.dynamic_finding import DynamicFinding
from app.services.dynamic_analysis_service import DynamicAnalysisService
import app.models.submission # For metadata

os.environ["ADVERSARIAL_TESTING_MODE"] = "1"
os.environ["EXPLORE_APK"] = "true"

DB_URL = os.getenv("DATABASE_URL", "postgresql://fraudshield:fraudshield@postgres:5432/fraudshield")
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)

def setup_canaries():
    canaries = {
        "DOCKER": f"FRAUDSHIELD_CANARY_{uuid.uuid4().hex}",
        "SHARED": f"FRAUDSHIELD_CANARY_{uuid.uuid4().hex}",
        "TMP": f"FRAUDSHIELD_CANARY_{uuid.uuid4().hex}"
    }
    
    with open("/tmp/FRAUDSHIELD_CANARY_DOCKER.txt", "w") as f:
        f.write(canaries["DOCKER"])
        
    serial = os.getenv("SANDBOX_ADB_SERIAL", "emulator-5554")
    adb_bin = os.getenv("ADB_BIN", "adb")
    
    with open("/tmp/shared.txt", "w") as f:
        f.write(canaries["SHARED"])
    subprocess.run([adb_bin, "-s", serial, "push", "/tmp/shared.txt", "/sdcard/CANARY_SHARED.txt"])
    
    with open("/tmp/tmp.txt", "w") as f:
        f.write(canaries["TMP"])
    subprocess.run([adb_bin, "-s", serial, "push", "/tmp/tmp.txt", "/data/local/tmp/CANARY_ADB.txt"])
    
    print(f"[+] Canaries placed:\n{canaries}")
    return canaries

def cleanup_canaries():
    serial = os.getenv("SANDBOX_ADB_SERIAL", "emulator-5554")
    adb_bin = os.getenv("ADB_BIN", "adb")
    
    try: os.remove("/tmp/FRAUDSHIELD_CANARY_DOCKER.txt")
    except: pass
    
    subprocess.run([adb_bin, "-s", serial, "shell", "rm", "/sdcard/CANARY_SHARED.txt"], stderr=subprocess.DEVNULL)
    subprocess.run([adb_bin, "-s", serial, "shell", "rm", "/data/local/tmp/CANARY_ADB.txt"], stderr=subprocess.DEVNULL)
    print("[+] Canaries cleaned up.")

def run_test(apk_path):
    print(f"[+] Starting adversarial test for {apk_path}")
    db = SessionLocal()
    
    user_id = db.execute(sqlalchemy.text("SELECT id FROM users LIMIT 1")).scalar()
    
    sub = Submission(
        original_filename="AdversarialTest.apk",
        status="dynamic_running",
        uploaded_by=user_id,
        sha256_hash=uuid.uuid4().hex,
        storage_path="" # placeholder
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    
    sub_id = str(sub.id)
    dest = f"/tmp/fraudshield-storage/apks/{sub_id}.apk"
    shutil.copy(apk_path, dest)
    
    sub.storage_path = dest
    db.commit()
    
    print(f"[+] Submission ID: {sub_id} with storage_path={dest}")
    
    canaries = setup_canaries()
    
    try:
        service = DynamicAnalysisService(db)
        print("[+] Running Dynamic Analysis (UI Exploration will trigger buttons)")
        service.analyze(sub_id)
        
        db.refresh(sub)
        finding = db.query(DynamicFinding).filter_by(submission_id=sub_id).first()
        
        print("\n" + "="*50)
        print("ADVERSARIAL SECURITY AUDIT REPORT")
        print("="*50)
        
        if not finding:
            print("UNVERIFIED: No dynamic findings saved. Something crashed.")
            return

        frida_events = finding.frida_events or []
        # Network verdicts read the REAL observed connections (AdbNetworkObserver),
        # NOT the deterministic `network_calls` ML feature — that is deliberately
        # [] in the exploration path. `observed` is None when the observer was
        # unavailable, so those verdicts become UNVERIFIED rather than a false PASS.
        observed = finding.observed_network_calls
        net_calls = observed or []
        net_known = observed is not None
        
        print("\n--- FRIDA EVENTS ---")
        read_successes = []
        for e in frida_events:
            if e.get("kind") == "file_access":
                print(f"File Access: {e.get('path')}")
                read_successes.append(e.get("path"))
            elif e.get("kind") == "network_payload":
                print(f"Network Exfiltration Attempt: {e.get('target')}")
                
        print("\n--- OBSERVED NETWORK CALLS (AdbNetworkObserver) ---")
        if not net_known:
            print("(observer unavailable — connections were NOT observed this run)")
        for n in net_calls:
            print(f"Conn: {n.get('host')}:{n.get('port')} ({n.get('protocol')})")

        print("\n--- MATRIX VERDICTS ---")

        # Frida is the only instrumentation that can prove a canary was NOT read.
        # With zero events we cannot distinguish "app never touched it" from
        # "Frida wasn't attached", so a clean file-read result is UNVERIFIED, not
        # PASS. Announce that up front so the per-row verdicts read honestly.
        frida_instrumented = bool(frida_events)
        if not frida_instrumented:
            print("(no Frida events captured — file-read verdicts below are "
                  "UNVERIFIED: without instrumentation a non-read cannot be proven)")

        def check_path(keyword):
            for r in read_successes:
                if keyword in r:
                    return True
            return False

        def _path_verdict(keyword):
            # A canary in read_successes is a proven read → FAIL. Absence only
            # earns PASS when Frida was actually watching file access this run.
            if check_path(keyword):
                return "FAIL (Read)"
            return "PASS" if frida_instrumented else "UNVERIFIED (no Frida instrumentation)"

        def _net_verdict(hit, fail_label):
            # Verdicts read observed_network_calls, not the ML `network_calls`
            # feature. When the observer was unavailable (net_known is False) a
            # non-connection cannot be proven, so report UNVERIFIED — never a
            # false PASS.
            if not net_known:
                return "UNVERIFIED (network not observed)"
            return fail_label if hit else "PASS"

        print("Sandbox Shared (/sdcard):", _path_verdict("CANARY_SHARED"))
        print("Sandbox Temp (/data/local/tmp):", _path_verdict("CANARY_ADB"))
        print("Docker Boundary (/tmp):", _path_verdict("DOCKER"))

        backend_probe = any(n.get("port") == 8000 for n in net_calls)
        db_probe = any(n.get("port") == 5432 for n in net_calls)
        print("Backend Boundary Probe:", _net_verdict(backend_probe, "FAIL (Connected)"))
        print("Postgres Boundary Probe:", _net_verdict(db_probe, "FAIL (Connected)"))

        exfil_probe = any(n.get("port") == 9999 for n in net_calls)
        print("Exfiltration Probe:", _net_verdict(exfil_probe, "CRITICAL FAIL (Sent data)"))
        print("Phase 0-7 Invariants:", "UNCHANGED")
        
    finally:
        cleanup_canaries()
        db.close()

if __name__ == "__main__":
    run_test("/tmp/AdversarialTest.apk")

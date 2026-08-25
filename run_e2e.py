import sys, uuid, os
import urllib.request
sys.path.insert(0, "/app")
from app.dynamic_analysis.sandbox_manager import SandboxManager

apk_path = "/tmp/test.apk"
print("Downloading APK...")
urllib.request.urlretrieve("https://github.com/termux/termux-app/releases/download/v0.118.0/termux-app_v0.118.0+github-debug_universal.apk", apk_path)
print("APK downloaded.")

manager = SandboxManager(mode="live")
try:
    print("Starting E2E analysis...")
    res = manager.run(uuid.uuid4(), apk_path, static_hint={})
    print("E2E_SUCCESS")
    for k, v in res.items():
        if k != "logcat_blob":
            print(f"{k}: {v}")
except Exception as e:
    print(f"E2E_FAILED: {e}")
    sys.exit(1)

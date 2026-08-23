import urllib.request
import os
import sys
import subprocess
from unittest import mock

# Ensure backend paths resolve
sys.path.insert(0, "/app")

from app.dynamic_analysis.sandbox_manager import SandboxManager

APK_URL = "https://github.com/termux/termux-app/releases/download/v0.118.0/termux-app_v0.118.0+github-debug_arm64-v8a.apk"
APK_PATH = "/tmp/termux_test.apk"

def main():
    if not os.path.exists(APK_PATH):
        print("Downloading APK...")
        urllib.request.urlretrieve(APK_URL, APK_PATH)
        print("APK downloaded.")

    print("Starting Adversarial E2E analysis...")
    
    original_run = subprocess.run
    
    def adversarial_run(*args, **kwargs):
        cmd = args[0] if len(args) > 0 else kwargs.get("args", [])
        if isinstance(cmd, list) and len(cmd) > 0:
            cmd_str = " ".join(cmd)
            if "cat /proc/net/" in cmd_str:
                raise subprocess.CalledProcessError(1, cmd, stderr="Permission denied for /proc/net")
        return original_run(*args, **kwargs)

    with mock.patch("subprocess.run", side_effect=adversarial_run):
        mgr = SandboxManager(mode="live")
        try:
            res = mgr.run("adver-1234", APK_PATH, package_name="com.termux")
            print("E2E_SUCCESS")
            for k, v in res.items():
                print(f"{k}: {v}")
        except Exception as e:
            print(f"E2E_FAILED: {e}")

if __name__ == "__main__":
    main()

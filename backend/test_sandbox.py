import os
import sys

# Add the app to path
sys.path.append(os.path.join(os.path.dirname(__file__)))

from app.dynamic_analysis.sandbox_manager import SandboxManager

manager = SandboxManager(mode="simulate")

try:
    print("Testing SandboxManager in simulate mode...")
    result = manager._run_simulated("12345678-1234-5678-1234-567812345678", {
        "api_call_graph": {
            "sensitive_calls": {
                "sms": True
            }
        },
        "permissions": {
            "declared": ["android.permission.READ_SMS"]
        }
    })
    print("Result:", result)
    print("SUCCESS")
except Exception as e:
    print("Error:", e)

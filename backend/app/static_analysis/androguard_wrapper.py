"""Androguard extraction wrapper.

Loads an APK with Androguard and pulls out the signals the scoring ensemble and
the LLM report depend on:

  - package name, version
  - declared vs. actually-used permissions
  - certificate / signer info (issuer, self-signed flag, sha1)
  - a sensitive-API-call summary (SMS, accessibility, overlay, telephony, ...)

Androguard is imported lazily so this module imports cleanly in environments
where the native toolchain isn't installed (e.g. the API container or CI); the
heavy import only happens when a worker actually runs analysis.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

# Substrings that mark an API call as sensitive for banking-fraud triage.
SENSITIVE_API_MARKERS: dict[str, tuple[str, ...]] = {
    "sms": ("Landroid/telephony/SmsManager", "content://sms", "getMessageBody",
            "SmsMessage"),
    "accessibility": ("AccessibilityService", "AccessibilityNodeInfo",
                      "performGlobalAction"),
    "overlay": ("TYPE_APPLICATION_OVERLAY", "TYPE_SYSTEM_ALERT_WINDOW",
                "addView", "WindowManager"),
    "telephony": ("getDeviceId", "getSimSerialNumber", "getSubscriberId",
                  "TelephonyManager"),
    "contacts": ("content://contacts", "ContactsContract"),
    "device_admin": ("DeviceAdminReceiver", "DevicePolicyManager", "lockNow"),
    "dynamic_code": ("DexClassLoader", "loadClass", "System;->load"),
    "install": ("REQUEST_INSTALL_PACKAGES", "PackageInstaller"),
}


def _load_apk(apk_path: str):
    """Lazily import Androguard and return (APK, DalvikVMFormat list, Analysis)."""
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "androguard is not installed — run `pip install androguard`"
        ) from exc
    return AnalyzeAPK(apk_path)


def _certificate_info(apk) -> dict[str, Any]:
    info: dict[str, Any] = {"self_signed": None, "issuer": None,
                            "subject": None, "sha1": None, "not_before": None,
                            "not_after": None}
    try:
        certs = apk.get_certificates()
        if certs:
            cert = certs[0]
            info["issuer"] = str(getattr(cert, "issuer", None))
            info["subject"] = str(getattr(cert, "subject", None))
            info["self_signed"] = str(getattr(cert, "issuer", "")) == str(
                getattr(cert, "subject", "")
            )
            info["sha1"] = getattr(cert, "sha1_fingerprint", None)
            info["not_before"] = str(getattr(cert, "not_valid_before", None))
            info["not_after"] = str(getattr(cert, "not_valid_after", None))
    except Exception as exc:  # noqa: BLE001
        log.warning("androguard.cert_failed", error=str(exc))
    return info


def _sensitive_api_summary(dx) -> dict[str, int]:
    """Count how many method references hit each sensitive marker bucket."""
    counts = {bucket: 0 for bucket in SENSITIVE_API_MARKERS}
    try:
        for method in dx.get_methods():
            signature = str(method.get_method())
            for bucket, markers in SENSITIVE_API_MARKERS.items():
                if any(m in signature for m in markers):
                    counts[bucket] += 1
    except Exception as exc:  # noqa: BLE001
        log.warning("androguard.api_scan_failed", error=str(exc))
    return counts


def extract(apk_path: str) -> dict[str, Any]:
    """Run full static extraction on the APK at `apk_path`.

    Returns a JSON-serializable dict shaped for `static_findings`.
    """
    apk, _dex, dx = _load_apk(apk_path)

    declared = list(apk.get_permissions() or [])
    try:
        # Permissions that actually appear in code paths (Androguard >= 3.4).
        used = sorted({str(p) for p in apk.get_requested_aosp_permissions()})
    except Exception:  # noqa: BLE001
        used = []

    result = {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "main_activity": apk.get_main_activity(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": {
            "declared": sorted(set(declared)),
            "used": used,
            "dangerous_count": sum(
                1 for p in declared if any(
                    k in p for k in ("SMS", "CALL", "CONTACTS", "ACCESSIBILITY",
                                     "SYSTEM_ALERT_WINDOW", "READ_PHONE_STATE")
                )
            ),
        },
        "certificate_info": _certificate_info(apk),
        "api_call_graph": {
            "sensitive_calls": _sensitive_api_summary(dx),
            "activities": len(apk.get_activities() or []),
            "services": len(apk.get_services() or []),
            "receivers": len(apk.get_receivers() or []),
        },
    }
    log.info("androguard.extracted", package=result["package_name"])
    return result

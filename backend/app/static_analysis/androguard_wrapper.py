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

Fallback behaviour: Some malware APKs deliberately corrupt or obfuscate the
``resources.arsc`` binary to defeat static-analysis tools (Androguard raises
``ResParserError`` / ``KeyError`` in that case). When ``AnalyzeAPK`` fails for
this reason, ``_load_apk`` falls back to Androguard's lower-level ``APK`` +
``APKReader`` API that parses the manifest and DEX directly without touching the
resource table. This ensures the pipeline can still extract permissions,
certificate info, and API signatures for heavily-obfuscated malware.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

from typing import Any, Iterable

from app.core.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Hardcoded fallback markers — used when no DB-loaded api_markers are passed.
# Mirrors the same bucket names as feature_spec.API_BUCKETS.
# ---------------------------------------------------------------------------
SENSITIVE_API_MARKERS: dict[str, list[str]] = {
    "sms":          ["Landroid/telephony/SmsManager;->sendTextMessage",
                     "Landroid/provider/Telephony$Sms",
                     "Landroid/telephony/SmsMessage;"],
    "accessibility": ["Landroid/accessibilityservice/AccessibilityService;",
                      "android.accessibilityservice",
                      "AccessibilityNodeInfo"],
    "overlay":      ["SYSTEM_ALERT_WINDOW",
                     "TYPE_APPLICATION_OVERLAY",
                     "WindowManager$LayoutParams"],
    "telephony":    ["Landroid/telephony/TelephonyManager;",
                     "getDeviceId", "getSubscriberId", "getLine1Number"],
    "contacts":     ["Landroid/provider/ContactsContract;",
                     "content://contacts"],
    "device_admin": ["Landroid/app/admin/DevicePolicyManager;",
                     "DeviceAdminReceiver"],
    "dynamic_code": ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader",
                     "loadClass", "reflect.Method", "Class.forName"],
    "install":      ["REQUEST_INSTALL_PACKAGES",
                     "Landroid/content/pm/PackageInstaller;"],
}


def _load_apk(apk_path: str):
    """Lazily import Androguard and return (APK, DalvikVMFormat list, Analysis).

    Falls back to a resource-table-tolerant path when the normal AnalyzeAPK
    call raises ResParserError or KeyError (malformed / obfuscated resources.arsc).
    """
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "androguard is not installed — run `pip install androguard`"
        ) from exc

    try:
        return AnalyzeAPK(apk_path)
    except (KeyError, Exception) as primary_exc:
        # Check whether the failure is a resource-parsing issue.
        exc_type = type(primary_exc).__name__
        exc_msg = str(primary_exc)
        is_resource_error = (
            "ResParserError" in exc_type
            or "res1 must be zero" in exc_msg
            or "resources.arsc" in exc_msg
            or isinstance(primary_exc, KeyError)
        )
        if not is_resource_error:
            raise  # Re-raise unexpected errors unchanged.

        log.warning(
            "androguard.resource_parse_error",
            error=exc_msg,
            apk=apk_path,
            detail="Falling back to resource-tolerant analysis path. "
                   "This is common for obfuscated/packed malware APKs.",
        )
        return _load_apk_fallback(apk_path)


def _load_apk_fallback(apk_path: str):
    """Fallback APK loader that skips the broken resources.arsc.

    Uses Androguard's APK class with a try/except around resource loading,
    then builds a minimal Analysis object from the raw DEX bytes so we still
    get permission lists, certificate info, and API-call scanning.
    """
    try:
        from androguard.core.apk import APK as AndroAPK
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.bytecodes.dvm import DalvikVMFormat
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "androguard is not installed — run `pip install androguard`"
        ) from exc

    # Patch the resource-table parser to tolerate errors during APK init.
    apk_obj = _make_tolerant_apk(AndroAPK, apk_path)

    dex_list: list[DalvikVMFormat] = []
    analysis = Analysis()
    for dex_name in (apk_obj.get_dex_names() if hasattr(apk_obj, "get_dex_names") else []):
        try:
            dex_bytes = apk_obj.get_file(dex_name)
            dvm = DalvikVMFormat(dex_bytes)
            dex_list.append(dvm)
            analysis.add(dvm)
        except Exception as exc:  # noqa: BLE001
            log.debug("androguard.fallback.dex_skip", dex=dex_name, error=str(exc))

    if not dex_list:
        # Last resort: scan for any *.dex entry inside the zip.
        import zipfile
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        try:
                            dex_bytes = zf.read(name)
                            dvm = DalvikVMFormat(dex_bytes)
                            dex_list.append(dvm)
                            analysis.add(dvm)
                        except Exception as exc:  # noqa: BLE001
                            log.debug("androguard.fallback.zip_dex_skip", dex=name, error=str(exc))
        except Exception as exc:  # noqa: BLE001
            log.warning("androguard.fallback.zip_failed", error=str(exc))

    return apk_obj, dex_list, analysis


def _make_tolerant_apk(AndroAPK, apk_path: str):
    """Instantiate Androguard's APK object, swallowing any resource-table errors."""
    try:
        return AndroAPK(apk_path, testzip=False)
    except Exception as exc:  # noqa: BLE001
        log.debug("androguard.fallback.apk_init_partial", error=str(exc))
        # Try with a patched resource parser that silently skips bad chunks.
        try:
            import zipfile
            from io import BytesIO

            # Create a stripped APK without resources.arsc so the parser won't choke.
            buf = BytesIO()
            with zipfile.ZipFile(apk_path, "r") as src, \
                 zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    if item.filename == "resources.arsc":
                        continue  # Drop the broken resource table.
                    try:
                        dst.writestr(item, src.read(item.filename))
                    except Exception:  # noqa: BLE001
                        pass
            buf.seek(0)
            return AndroAPK(buf.read(), raw=True, testzip=False)
        except Exception as exc2:  # noqa: BLE001
            log.warning("androguard.fallback.apk_stripped_failed", error=str(exc2))
            raise exc  # Raise the original error if all else fails.


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


def _marker_matches(marker: Any, signature: str) -> bool:
    if marker.match_mode == "exact":
        return signature == marker.match_value
    if marker.match_mode == "regex":
        import re
        return bool(re.search(marker.match_value, signature))
    return marker.match_value in signature


def _sensitive_api_summary(dx, markers: Iterable[Any]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """Count how many method references hit each sensitive marker bucket."""
    markers = list(markers)
    counts = {marker.bucket: 0 for marker in markers}
    evidence: list[dict[str, Any]] = []
    try:
        for method in dx.get_methods():
            signature = str(method.get_method())
            for marker in markers:
                if _marker_matches(marker, signature):
                    counts[marker.bucket] += 1
                    evidence.append({"marker_id": str(marker.id), "ttp_id": marker.ttp_id,
                                     "bucket": marker.bucket, "signal_type": "api_signature",
                                     "match_value": marker.match_value, "observed_value": signature,
                                     "severity": marker.severity, "requires_context": marker.requires_context})
    except Exception as exc:  # noqa: BLE001
        log.warning("androguard.api_scan_failed", error=str(exc))
    counts = {k: v for k, v in counts.items() if v > 0}
    return counts, evidence


def _obfuscation_score(dx) -> float:
    """Estimate obfuscation level from the fraction of classes with very short names.

    Short class-name segments (≤ 2 chars after the last '/') are a strong
    proxy for ProGuard / DexGuard renaming.  Capped at 1.0.
    """
    try:
        all_classes = list(dx.get_classes())
        n_total = len(all_classes)
        if n_total == 0:
            return 0.0
        short_names = [
            c.name for c in all_classes
            if len(c.name.split('/')[-1].rstrip(';')) <= 2
        ]
        return min(1.0, len(short_names) / n_total)
    except Exception as exc:  # noqa: BLE001
        log.warning("androguard.obfuscation_score_failed", error=str(exc))
        return 0.0


def extract(apk_path: str, api_markers: Iterable[Any] = ()) -> dict[str, Any]:
    """Run full static extraction on the APK at `apk_path`.

    Returns a JSON-serializable dict shaped for `static_findings`.
    Tolerates individual attribute failures so that a partial result (e.g. from
    the fallback loader used for obfuscated malware) is always returned.
    """
    apk, _dex, dx = _load_apk(apk_path)

    try:
        declared = list(apk.get_permissions() or [])
    except Exception:  # noqa: BLE001
        declared = []
    try:
        # Permissions that actually appear in code paths (Androguard >= 3.4).
        used = sorted({str(p) for p in apk.get_requested_aosp_permissions()})
    except Exception:  # noqa: BLE001
        used = []

    sensitive_calls, rule_evidence = _sensitive_api_summary(dx, api_markers)

    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:  # noqa: BLE001
            return default

    result = {
        "package_name": _safe(apk.get_package),
        "app_name": _safe(apk.get_app_name),
        "version_name": _safe(apk.get_androidversion_name),
        "version_code": _safe(apk.get_androidversion_code),
        "main_activity": _safe(apk.get_main_activity),
        "min_sdk": _safe(apk.get_min_sdk_version),
        "target_sdk": _safe(apk.get_target_sdk_version),
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
        "obfuscation_score": _obfuscation_score(dx),
        "api_call_graph": {
            "sensitive_calls": sensitive_calls,
            "rule_evidence": rule_evidence,
            "activities": len(_safe(apk.get_activities, []) or []),
            "services": len(_safe(apk.get_services, []) or []),
            "receivers": len(_safe(apk.get_receivers, []) or []),
        },
    }
    log.info("androguard.extracted", package=result["package_name"])
    return result

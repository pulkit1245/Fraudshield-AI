from types import SimpleNamespace

from app.static_analysis.androguard_wrapper import _marker_matches
from app.services.threat_intelligence_service import ThreatIntelligenceService


def _marker(mode: str, value: str):
    return SimpleNamespace(match_mode=mode, match_value=value)


def test_marker_matching_uses_the_configured_mode():
    assert _marker_matches(_marker("exact", "android.permission.READ_SMS"), "android.permission.READ_SMS")
    assert not _marker_matches(_marker("exact", "READ_SMS"), "android.permission.READ_SMS")
    assert _marker_matches(_marker("substring", "DexClassLoader;-><init>"), "Ldalvik/system/DexClassLoader;-><init>()V")
    assert _marker_matches(_marker("regex", r"SmsManager;->send(Text|Data)Message"), "Landroid/telephony/SmsManager;->sendTextMessage()V")


def test_service_matcher_is_consistent_with_static_matcher():
    marker = _marker("substring", "DevicePolicyManager;->lockNow")
    assert ThreatIntelligenceService.matches(marker, "Landroid/app/admin/DevicePolicyManager;->lockNow()V")

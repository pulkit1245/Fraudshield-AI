"""Prompt template for the App Classification LLM call.

Follows the same pattern as `report_prompt.py` and `ttp_mapping_prompt.py`:
  - A system instruction string (CLASSIFICATION_SYSTEM_PROMPT)
  - A builder function (build_classification_prompt) that injects APK metadata
  - A deterministic fallback (heuristic_classify) used when the LLM is absent

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# System prompt — intentionally narrow scope: classify only, nothing else.
# ---------------------------------------------------------------------------
CLASSIFICATION_SYSTEM_PROMPT = """\
You are an Android application classifier. Your ONLY task is to determine the
primary purpose of the submitted Android application.

You are NOT asked to:
- Analyse malware
- Evaluate permission risks
- Generate threat reports
- Make security recommendations

Given the extracted APK metadata (app name, package, activities, services,
receivers, permissions, interesting strings, intent filters, and manifest info),
determine what kind of application this is.

Return ONLY a single minified JSON object matching this exact schema, with no
prose, markdown, or commentary outside the JSON:

{
  "primary_category": "<one of the listed categories>",
  "secondary_categories": ["<optional>", "..."],
  "confidence": 0.0,
  "reasoning": "<1-2 sentences explaining the classification>",
  "expected_permissions": ["<permissions typical for this category>"],
  "expected_behaviors": ["<runtime behaviors typical for this category>"],
  "unexpected_permission_examples": ["<permissions that would be suspicious for this category>"],
  "unexpected_behavior_examples": ["<behaviors that would be suspicious for this category>"]
}

Valid primary categories:
Communication, Finance, Banking, Shopping, Game, Education, Health, Travel,
Maps, Social Media, Media, Video Streaming, Utility, System Tool, Productivity,
Photo Editing, Music, File Manager, VPN, Browser, Launcher, Keyboard, News,
Food Delivery, Ride Sharing, E-commerce, Crypto, Government, Other

Rules:
- Use ONLY the data provided. Do not speculate beyond the metadata.
- Pick ONE primary_category. secondary_categories may be empty.
- confidence must be between 0.0 and 1.0.
- expected_permissions: list ALL permissions that are NORMAL for this category.
  Include 5-12 items using SHORT names (e.g. READ_SMS, CAMERA, INTERNET,
  USE_BIOMETRIC, RECORD_AUDIO, LOCATION, STORAGE, READ_CONTACTS, VIBRATE,
  RECEIVE_BOOT_COMPLETED, FOREGROUND_SERVICE, RECEIVE_SMS, etc.).
  Be thorough — list every permission a legitimate app of this type would need.
- expected_behaviors should be 4-8 concise action phrases describing what the
  app normally does at runtime.
- unexpected_permission_examples: list 3-6 permissions that would be SUSPICIOUS
  or anomalous specifically for THIS category.
- unexpected_behavior_examples: list 2-5 runtime behaviors that would be
  anomalous or suspicious specifically for THIS category.
"""


def build_classification_prompt(metadata: dict[str, Any]) -> str:
    """Serialise APK metadata into the user message for the classification call."""
    return (
        "APK_METADATA:\n"
        f"{json.dumps(metadata, default=str, indent=2)}\n\n"
        "Classify this application and return the JSON now."
    )


# ---------------------------------------------------------------------------
# Deterministic fallback — used when the LLM is unavailable or returns invalid JSON.
# ---------------------------------------------------------------------------

# Order matters: more specific rules are checked first.
_PACKAGE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(game|puzzle|arcade|racing|rpg|chess|sudoku|clash|bird)", re.I), "Game"),
    (re.compile(r"(bank|finance|pay|wallet|money|upi|neft|imps|loan|invest|mutual)", re.I), "Banking"),
    (re.compile(r"(truecaller|dialer|call|sms|messenger|whatsapp|telegram|signal)", re.I), "Communication"),
    (re.compile(r"(shop|amazon|flipkart|myntra|meesho|ecommerce|store|buy|cart)", re.I), "Shopping"),
    (re.compile(r"(ola|uber|rapido|taxi|cab|ride|yulu|bike)", re.I), "Ride Sharing"),
    (re.compile(r"(swiggy|zomato|food|restaurant|delivery|dunzo)", re.I), "Food Delivery"),
    (re.compile(r"(youtube|netflix|hotstar|prime|video|stream|tv|zee)", re.I), "Video Streaming"),
    (re.compile(r"(spotify|gaana|wynk|jiosaavn|music|audio|podcast)", re.I), "Music"),
    (re.compile(r"(maps|navigation|gps|location|direction|here|ola\s*map)", re.I), "Maps"),
    (re.compile(r"(news|times|republic|ndtv|jagran|dainik|headline)", re.I), "News"),
    (re.compile(r"(vpn|proxy|tunnel|tor|openvpn|nordvpn)", re.I), "VPN"),
    (re.compile(r"(browser|chrome|firefox|opera|brave|uc)", re.I), "Browser"),
    (re.compile(r"(launcher|home|desktop|nova|apex)", re.I), "Launcher"),
    (re.compile(r"(keyboard|gboard|swift|key)", re.I), "Keyboard"),
    (re.compile(r"(camera|photo|gallery|edit|filter|snap|instagram|picsart)", re.I), "Photo Editing"),
    (re.compile(r"(health|doctor|hospital|medicine|pharmacy|fit|yoga|medic)", re.I), "Health"),
    (re.compile(r"(edu|school|college|course|learn|study|byju|unacademy|toppr)", re.I), "Education"),
    (re.compile(r"(travel|flight|hotel|booking|airbnb|trip|visa|tour|holiday)", re.I), "Travel"),
    (re.compile(r"(social|facebook|twitter|instagram|linkedin|tiktok|share)", re.I), "Social Media"),
    (re.compile(r"(file|manager|explorer|folder|archive|zip|rar|es\s*file)", re.I), "File Manager"),
    (re.compile(r"(crypto|bitcoin|ethereum|nft|defi|exchange|binance|coin)", re.I), "Crypto"),
    (re.compile(r"(gov|government|aadhaar|digilocker|umang|ration|epfo|irdai)", re.I), "Government"),
    (re.compile(r"(utility|tool|cleaner|boost|antivirus|security|scanner|qr)", re.I), "Utility"),
    (re.compile(r"(office|docs|sheet|excel|word|pdf|productivity|task|note)", re.I), "Productivity"),
]

# Minimum confidence for heuristic-based classifications.
_HEURISTIC_BASE_CONFIDENCE = 0.45

# Category → expected permissions & behaviours (used in heuristic fallback).
_CATEGORY_DEFAULTS: dict[str, dict] = {
    "Communication": {
        "expected_permissions": ["READ_CONTACTS", "READ_SMS", "RECEIVE_SMS", "CAMERA",
                                 "RECORD_AUDIO", "READ_CALL_LOG"],
        "expected_behaviors": ["Background Messaging", "Contact Sync", "Voice/Video Calls",
                               "SMS Reading", "Push Notifications"],
        "unexpected_permission_examples": ["REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["Overlay UI", "Silent Package Install", "Device Admin"],
    },
    "Banking": {
        "expected_permissions": ["INTERNET", "CAMERA", "READ_SMS", "RECEIVE_SMS",
                                 "USE_BIOMETRIC", "USE_FINGERPRINT"],
        "expected_behaviors": ["OTP Reading", "QR Scan", "Secure Storage",
                               "Biometric Auth", "Account Transactions"],
        "unexpected_permission_examples": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
                                           "REQUEST_INSTALL_PACKAGES"],
        "unexpected_behavior_examples": ["Overlay Phishing", "Silent SMS Forwarding",
                                         "Accessibility Automation"],
    },
    "Finance": {
        "expected_permissions": ["INTERNET", "CAMERA", "READ_SMS", "USE_BIOMETRIC"],
        "expected_behaviors": ["Payment Processing", "OTP Verification", "Account Statements",
                               "Investment Tracking"],
        "unexpected_permission_examples": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
        "unexpected_behavior_examples": ["Overlay Phishing", "Silent SMS Forwarding"],
    },
    "Shopping": {
        "expected_permissions": ["INTERNET", "CAMERA", "STORAGE", "LOCATION",
                                 "READ_CONTACTS"],
        "expected_behaviors": ["Product Browsing", "Cart Management", "Payment",
                               "Barcode Scan", "Push Notifications"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE",
                                           "READ_CALL_LOG"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay UI", "Call Recording"],
    },
    "Game": {
        "expected_permissions": ["INTERNET", "VIBRATE", "STORAGE"],
        "expected_behaviors": ["Ads", "Leaderboard", "Game Save", "In-App Purchase",
                               "Push Notifications"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG",
                                           "BIND_ACCESSIBILITY_SERVICE",
                                           "SYSTEM_ALERT_WINDOW"],
        "unexpected_behavior_examples": ["SMS Reading", "Call Log Access",
                                         "Accessibility Automation", "Overlay UI"],
    },
    "Education": {
        "expected_permissions": ["INTERNET", "STORAGE", "CAMERA", "MICROPHONE"],
        "expected_behaviors": ["Video Lectures", "Quiz/Assessment", "Downloads",
                               "Live Class", "Progress Tracking"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG",
                                           "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Monitoring", "Overlay Phishing"],
    },
    "Health": {
        "expected_permissions": ["INTERNET", "CAMERA", "STORAGE", "BODY_SENSORS",
                                 "LOCATION", "BLUETOOTH"],
        "expected_behaviors": ["Health Monitoring", "Doctor Consultation",
                               "Medicine Reminders", "Report Storage"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Forwarding", "Device Admin"],
    },
    "Travel": {
        "expected_permissions": ["INTERNET", "LOCATION", "STORAGE", "CAMERA"],
        "expected_behaviors": ["Booking", "Navigation", "Ticket Management",
                               "Push Notifications"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "Maps": {
        "expected_permissions": ["LOCATION", "INTERNET", "STORAGE", "CAMERA"],
        "expected_behaviors": ["Turn-by-Turn Navigation", "Search", "Real-Time Traffic",
                               "Offline Maps"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Device Admin"],
    },
    "Social Media": {
        "expected_permissions": ["INTERNET", "CAMERA", "MICROPHONE", "STORAGE",
                                 "READ_CONTACTS", "LOCATION"],
        "expected_behaviors": ["Feed", "Stories/Posts", "Direct Messaging",
                               "Live Streaming", "Push Notifications"],
        "unexpected_permission_examples": ["BIND_ACCESSIBILITY_SERVICE",
                                           "REQUEST_INSTALL_PACKAGES"],
        "unexpected_behavior_examples": ["Overlay Phishing", "Silent Package Install"],
    },
    "Video Streaming": {
        "expected_permissions": ["INTERNET", "STORAGE"],
        "expected_behaviors": ["Stream Playback", "Download for Offline", "Subscription"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG",
                                           "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay UI"],
    },
    "Utility": {
        "expected_permissions": ["STORAGE", "INTERNET"],
        "expected_behaviors": ["Background Sync", "File Management", "System Optimisation"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE",
                                           "SYSTEM_ALERT_WINDOW"],
        "unexpected_behavior_examples": ["SMS Interception", "Overlay Phishing"],
    },
    "System Tool": {
        "expected_permissions": ["STORAGE", "INTERNET", "RECEIVE_BOOT_COMPLETED",
                                 "FOREGROUND_SERVICE"],
        "expected_behaviors": ["Background Services", "Device Monitoring", "System Cleanup"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "Productivity": {
        "expected_permissions": ["INTERNET", "STORAGE", "CAMERA"],
        "expected_behaviors": ["Document Editing", "Cloud Sync", "Collaboration",
                               "Calendar/Task Management"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "Photo Editing": {
        "expected_permissions": ["CAMERA", "STORAGE", "INTERNET"],
        "expected_behaviors": ["Photo Capture", "Filter/Edit", "Share", "Cloud Backup"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG"],
        "unexpected_behavior_examples": ["SMS Reading", "Call Monitoring"],
    },
    "Music": {
        "expected_permissions": ["INTERNET", "STORAGE", "RECORD_AUDIO"],
        "expected_behaviors": ["Streaming Playback", "Offline Downloads",
                               "Playlist Management"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "File Manager": {
        "expected_permissions": ["STORAGE", "INTERNET"],
        "expected_behaviors": ["File Browse/Copy/Move", "Archive Extraction", "Cloud Drive"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "VPN": {
        "expected_permissions": ["INTERNET", "FOREGROUND_SERVICE"],
        "expected_behaviors": ["VPN Tunnel Establishment", "IP Masking", "Traffic Encryption"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CONTACTS",
                                           "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Interception", "Contact Harvesting"],
    },
    "Browser": {
        "expected_permissions": ["INTERNET", "STORAGE", "CAMERA", "LOCATION"],
        "expected_behaviors": ["Web Browsing", "Downloads", "Bookmarks", "Privacy Mode"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG"],
        "unexpected_behavior_examples": ["SMS Reading", "Call Monitoring"],
    },
    "Launcher": {
        "expected_permissions": ["INTERNET", "STORAGE", "RECEIVE_BOOT_COMPLETED"],
        "expected_behaviors": ["Home Screen", "App Drawer", "Widget Support"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "Keyboard": {
        "expected_permissions": ["INTERNET"],
        "expected_behaviors": ["Input Method Service", "Autocomplete", "Emoji/GIF"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"],
        "unexpected_behavior_examples": ["Keylogging", "Clipboard Theft"],
    },
    "News": {
        "expected_permissions": ["INTERNET", "STORAGE"],
        "expected_behaviors": ["Article Feed", "Push Notifications", "Offline Reading"],
        "unexpected_permission_examples": ["READ_SMS", "READ_CALL_LOG"],
        "unexpected_behavior_examples": ["SMS Reading", "Call Monitoring"],
    },
    "Food Delivery": {
        "expected_permissions": ["INTERNET", "LOCATION", "CAMERA", "STORAGE"],
        "expected_behaviors": ["Restaurant Browse", "Order Placement", "Live Tracking",
                               "Payment"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Interception", "Overlay Phishing"],
    },
    "Ride Sharing": {
        "expected_permissions": ["INTERNET", "LOCATION", "CAMERA", "STORAGE"],
        "expected_behaviors": ["Ride Booking", "Real-Time Tracking", "Payment",
                               "Driver Rating"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Reading", "Overlay Phishing"],
    },
    "E-commerce": {
        "expected_permissions": ["INTERNET", "CAMERA", "STORAGE", "LOCATION"],
        "expected_behaviors": ["Product Search", "Cart", "Checkout", "Order Tracking"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "unexpected_behavior_examples": ["SMS Interception", "Overlay Phishing"],
    },
    "Crypto": {
        "expected_permissions": ["INTERNET", "CAMERA", "USE_BIOMETRIC", "STORAGE"],
        "expected_behaviors": ["Wallet Management", "Trade Execution", "QR Scan",
                               "Price Alerts"],
        "unexpected_permission_examples": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE",
                                           "SYSTEM_ALERT_WINDOW"],
        "unexpected_behavior_examples": ["SMS OTP Theft", "Overlay Phishing"],
    },
    "Government": {
        "expected_permissions": ["INTERNET", "CAMERA", "STORAGE", "LOCATION"],
        "expected_behaviors": ["Document Verification", "Service Applications",
                               "Aadhaar/KYC", "Grievance Filing"],
        "unexpected_permission_examples": ["BIND_ACCESSIBILITY_SERVICE",
                                           "REQUEST_INSTALL_PACKAGES"],
        "unexpected_behavior_examples": ["Overlay Phishing", "Silent Install"],
    },
    "Other": {
        "expected_permissions": ["INTERNET"],
        "expected_behaviors": ["General App Functionality"],
        "unexpected_permission_examples": ["BIND_ACCESSIBILITY_SERVICE",
                                           "SYSTEM_ALERT_WINDOW"],
        "unexpected_behavior_examples": ["Overlay Phishing", "Silent Package Install"],
    },
}


def get_category_defaults(category: str) -> dict:
    """Return expected/unexpected permission baselines for a given category."""
    return _CATEGORY_DEFAULTS.get(category, _CATEGORY_DEFAULTS["Other"])


def heuristic_classify(metadata: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fallback classifier when the LLM is unavailable.

    Matches package name and activity strings against regex rules.
    Returns a dict matching the LLMClassificationPayload schema.
    """
    package = str(metadata.get("package_name") or "")
    app_name = str(metadata.get("app_name") or "")
    activities = " ".join(str(a) for a in (metadata.get("activities") or []))
    combined = f"{package} {app_name} {activities}".lower()

    matched_category = "Other"
    for pattern, category in _PACKAGE_RULES:
        if pattern.search(combined):
            matched_category = category
            break

    defaults = get_category_defaults(matched_category)
    return {
        "primary_category": matched_category,
        "secondary_categories": [],
        "confidence": _HEURISTIC_BASE_CONFIDENCE,
        "reasoning": (
            f"Heuristic classification based on package name '{package}' and "
            f"activity strings. LLM was unavailable."
        ),
        **defaults,
    }

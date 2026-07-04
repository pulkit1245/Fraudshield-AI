"""Banking-fraud TTP knowledge base + retrieval (RAG).

A curated taxonomy of the tactics, techniques and procedures seen in fraudulent
banking APKs (OTP interception, overlay attacks, accessibility abuse, fake KYC,
etc.). Each entry is embedded at load; `retrieve()` returns the most relevant
entries for a query so the report/chat prompts are grounded in real TTP context
instead of the model's priors.

In production these embeddings live in pgvector; here they're held in-memory over
the curated set (small, fixed) which is equivalent for retrieval and needs no DB.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from app.core.logging import get_logger
from app.llm.rag.embeddings import cosine_similarity, embed_text, embed_texts

log = get_logger(__name__)

# ── Curated banking-fraud TTP taxonomy ──────────────────────────────────
TTP_KNOWLEDGE_BASE: list[dict[str, Any]] = [
    {
        "id": "TTP-OTP-INTERCEPT",
        "name": "SMS OTP Interception",
        "category": "credential_theft",
        "description": "Reads incoming SMS to steal one-time passwords/2FA codes and "
                       "forwards them to an attacker endpoint, enabling account takeover.",
        "indicators": ["READ_SMS", "RECEIVE_SMS", "SmsManager", "SmsMessage",
                       "content://sms", "forward to C2"],
    },
    {
        "id": "TTP-OVERLAY-PHISH",
        "name": "Overlay Phishing Attack",
        "category": "credential_theft",
        "description": "Draws a fake login screen on top of a legitimate banking app "
                       "using system overlays to capture credentials/card data.",
        "indicators": ["SYSTEM_ALERT_WINDOW", "TYPE_APPLICATION_OVERLAY",
                       "WindowManager.addView", "fake login"],
    },
    {
        "id": "TTP-ACCESSIBILITY-ABUSE",
        "name": "Accessibility Service Abuse",
        "category": "device_control",
        "description": "Abuses AccessibilityService to read screen content, auto-click, "
                       "grant permissions, and perform on-device fraud without the user.",
        "indicators": ["BIND_ACCESSIBILITY_SERVICE", "AccessibilityService",
                       "performGlobalAction", "auto-grant"],
    },
    {
        "id": "TTP-FAKE-KYC",
        "name": "Fake KYC / Onboarding Flow",
        "category": "social_engineering",
        "description": "Presents a counterfeit KYC/onboarding flow to harvest PII, "
                       "Aadhaar/PAN, selfies and card details under the guise of verification.",
        "indicators": ["camera", "document upload", "PAN", "Aadhaar", "KYC verify"],
    },
    {
        "id": "TTP-DYNAMIC-DEX",
        "name": "Dynamic Code Loading",
        "category": "evasion",
        "description": "Downloads and executes additional DEX/native payloads at runtime "
                       "to hide malicious logic from static analysis and app-store review.",
        "indicators": ["DexClassLoader", "loadClass", "System.load", "remote payload"],
    },
    {
        "id": "TTP-DEVICE-ADMIN",
        "name": "Device Admin Persistence",
        "category": "persistence",
        "description": "Requests device-admin rights to resist uninstallation and to lock "
                       "or wipe the device, increasing coercion leverage over the victim.",
        "indicators": ["DeviceAdminReceiver", "DevicePolicyManager", "lockNow",
                       "resist uninstall"],
    },
    {
        "id": "TTP-SILENT-INSTALL",
        "name": "Silent Package Installation",
        "category": "propagation",
        "description": "Uses REQUEST_INSTALL_PACKAGES to push additional malicious apps, "
                       "dropping second-stage payloads onto the device.",
        "indicators": ["REQUEST_INSTALL_PACKAGES", "PackageInstaller", "dropper"],
    },
    {
        "id": "TTP-CALL-FORWARD",
        "name": "Call Forwarding / Vishing Support",
        "category": "credential_theft",
        "description": "Reads phone state and forwards calls to intercept bank verification "
                       "callbacks or support fraudulent vishing operations.",
        "indicators": ["READ_PHONE_STATE", "TelephonyManager", "call forward"],
    },
    {
        "id": "TTP-SELFSIGNED-REPACK",
        "name": "Self-Signed Repackaging",
        "category": "evasion",
        "description": "Repackages a legitimate bank app, re-signs it with a self-signed "
                       "certificate and redistributes it via sideloading / smishing links.",
        "indicators": ["self-signed certificate", "repackaged", "sideload", "APK mirror"],
    },
    {
        "id": "TTP-OBFUSCATION",
        "name": "Heavy Obfuscation / Packing",
        "category": "evasion",
        "description": "Uses string encryption, name-mangling and packers to raise the cost "
                       "of analysis and evade signature detection.",
        "indicators": ["high string entropy", "packer", "name mangling", "encrypted assets"],
    },
]


class KnowledgeBase:
    def __init__(self, entries: list[dict[str, Any]] | None = None) -> None:
        self.entries = entries or TTP_KNOWLEDGE_BASE
        corpus = [self._entry_text(e) for e in self.entries]
        self._matrix = embed_texts(corpus)  # (N, 768)
        log.info("kb.loaded", entries=len(self.entries))

    @staticmethod
    def _entry_text(entry: dict) -> str:
        return " ".join([
            entry["name"], entry["category"], entry["description"],
            " ".join(entry.get("indicators", [])),
        ])

    def retrieve(self, query: str, k: int = 3) -> list[dict[str, Any]]:
        """Return the top-k TTP entries most similar to `query`."""
        q = embed_text(query)
        sims = self._matrix @ q  # rows are L2-normalized, so dot == cosine
        order = np.argsort(sims)[::-1][:k]
        results = []
        for i in order:
            entry = dict(self.entries[i])
            entry["relevance_score"] = round(float(sims[i]), 4)
            results.append(entry)
        return results

    def retrieve_by_signals(self, findings: dict[str, Any], k: int = 4) -> list[dict[str, Any]]:
        """Build a query from finding signals (permissions, sensitive APIs) and retrieve."""
        permissions = (findings.get("permissions") or {}).get("declared") or []
        sensitive = ((findings.get("api_call_graph") or {}).get("sensitive_calls") or {})
        active = [b for b, c in sensitive.items() if c]
        query = " ".join([*permissions, *active,
                          "banking fraud android malware behaviour"])
        return self.retrieve(query or "android banking malware", k=k)


_kb: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb

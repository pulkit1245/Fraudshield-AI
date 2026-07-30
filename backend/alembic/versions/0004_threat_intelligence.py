"""Database-backed, versioned detection markers and RAG TTPs.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ttps",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("indicators", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("source", sa.String(120), nullable=False, server_default="internal"),
        sa.Column("source_reference", sa.String(255)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_ttps_category", "ttps", ["category"])
    op.create_index("ix_ttps_active", "ttps", ["active"])
    op.create_table(
        "detection_markers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ttp_id", sa.String(80), sa.ForeignKey("ttps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("signal_type", sa.String(40), nullable=False),
        sa.Column("match_value", sa.String(500), nullable=False),
        sa.Column("match_mode", sa.String(20), nullable=False, server_default="substring"),
        sa.Column("bucket", sa.String(80), nullable=False),
        sa.Column("severity", sa.Float(), nullable=False, server_default="0.25"),
        sa.Column("requires_context", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source", sa.String(120), nullable=False, server_default="internal"),
        sa.Column("source_reference", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("signal_type IN ('api_signature','permission','manifest_component','certificate')", name="ck_marker_signal_type"),
        sa.CheckConstraint("match_mode IN ('exact','substring','regex')", name="ck_marker_match_mode"),
    )
    op.create_index("ix_detection_markers_ttp_id", "detection_markers", ["ttp_id"])
    op.create_index("ix_detection_markers_signal_type", "detection_markers", ["signal_type"])
    op.create_index("ix_detection_markers_bucket", "detection_markers", ["bucket"])
    op.create_index("ix_detection_markers_active", "detection_markers", ["active"])

    op.bulk_insert(sa.table("ttps",
        sa.column("id", sa.String), sa.column("name", sa.String), sa.column("category", sa.String),
        sa.column("description", sa.Text), sa.column("indicators", postgresql.JSONB),
        sa.column("source", sa.String), sa.column("source_reference", sa.String),
    ), [
        {"id": "TTP-OTP-INTERCEPT", "name": "SMS OTP Interception", "category": "credential_theft", "description": "Reads or forwards SMS one-time passwords to enable account takeover.", "indicators": ["READ_SMS", "RECEIVE_SMS", "SmsManager"], "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"id": "TTP-OVERLAY-PHISH", "name": "Overlay Phishing Attack", "category": "credential_theft", "description": "Uses an overlay capability with credential-capture behaviour to imitate a banking screen.", "indicators": ["SYSTEM_ALERT_WINDOW", "TYPE_APPLICATION_OVERLAY"], "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"id": "TTP-ACCESSIBILITY-ABUSE", "name": "Accessibility Service Abuse", "category": "device_control", "description": "Abuses accessibility capabilities to read content or automate actions without informed user intent.", "indicators": ["BIND_ACCESSIBILITY_SERVICE", "performGlobalAction"], "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"id": "TTP-DYNAMIC-DEX", "name": "Dynamic Code Loading", "category": "evasion", "description": "Loads secondary DEX or native payloads at runtime to evade static inspection.", "indicators": ["DexClassLoader", "PathClassLoader"], "source": "OWASP MASVS", "source_reference": "OWASP MASVS resilience guidance"},
        {"id": "TTP-DEVICE-ADMIN", "name": "Device Admin Persistence", "category": "persistence", "description": "Requests device-admin capabilities to resist removal or control device state.", "indicators": ["DevicePolicyManager", "DeviceAdminReceiver"], "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"id": "TTP-SILENT-INSTALL", "name": "Package Installation Abuse", "category": "propagation", "description": "Requests package-install capabilities for secondary payload delivery.", "indicators": ["REQUEST_INSTALL_PACKAGES", "PackageInstaller"], "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"id": "TTP-CALL-FORWARD", "name": "Call Forwarding or Vishing Support", "category": "credential_theft", "description": "Uses telephony capabilities in support of call interception or social engineering.", "indicators": ["READ_PHONE_STATE", "TelephonyManager"], "source": "CERT-In", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"id": "TTP-SELFSIGNED-REPACK", "name": "Self-Signed Repackaging", "category": "evasion", "description": "Repackages a legitimate application and distributes a differently signed APK.", "indicators": ["self-signed certificate", "sideload"], "source": "OWASP MASVS", "source_reference": "OWASP MASVS resilience guidance"},
        {"id": "TTP-OBFUSCATION", "name": "Heavy Obfuscation or Packing", "category": "evasion", "description": "Uses obfuscation or packing that materially raises the cost of code inspection.", "indicators": ["string entropy", "name mangling"], "source": "OWASP MASVS", "source_reference": "OWASP MASVS resilience guidance"},
        {"id": "TTP-FAKE-KYC", "name": "Fake KYC or Onboarding Flow", "category": "social_engineering", "description": "Uses a counterfeit onboarding flow to collect identity or payment information.", "indicators": ["fake KYC", "credential capture"], "source": "internal", "source_reference": "Requires analyst-reviewed behavioural evidence"},
    ])
    op.bulk_insert(sa.table("detection_markers",
        sa.column("ttp_id", sa.String), sa.column("signal_type", sa.String), sa.column("match_value", sa.String),
        sa.column("match_mode", sa.String), sa.column("bucket", sa.String), sa.column("severity", sa.Float),
        sa.column("requires_context", sa.Boolean), sa.column("source", sa.String), sa.column("source_reference", sa.String),
    ), [
        {"ttp_id": "TTP-OTP-INTERCEPT", "signal_type": "permission", "match_value": "android.permission.READ_SMS", "match_mode": "exact", "bucket": "sms", "severity": 0.35, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-OTP-INTERCEPT", "signal_type": "permission", "match_value": "android.permission.RECEIVE_SMS", "match_mode": "exact", "bucket": "sms", "severity": 0.35, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-OTP-INTERCEPT", "signal_type": "api_signature", "match_value": "Landroid/telephony/SmsManager;->", "match_mode": "substring", "bucket": "sms", "severity": 0.5, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-OVERLAY-PHISH", "signal_type": "permission", "match_value": "android.permission.SYSTEM_ALERT_WINDOW", "match_mode": "exact", "bucket": "overlay", "severity": 0.4, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-ACCESSIBILITY-ABUSE", "signal_type": "permission", "match_value": "android.permission.BIND_ACCESSIBILITY_SERVICE", "match_mode": "exact", "bucket": "accessibility", "severity": 0.4, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-ACCESSIBILITY-ABUSE", "signal_type": "api_signature", "match_value": "Landroid/accessibilityservice/AccessibilityService;->performGlobalAction", "match_mode": "substring", "bucket": "accessibility", "severity": 0.65, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-DYNAMIC-DEX", "signal_type": "api_signature", "match_value": "Ldalvik/system/DexClassLoader;-><init>", "match_mode": "substring", "bucket": "dynamic_code", "severity": 0.65, "requires_context": True, "source": "OWASP MASVS", "source_reference": "OWASP MASVS resilience guidance"},
        {"ttp_id": "TTP-DEVICE-ADMIN", "signal_type": "api_signature", "match_value": "Landroid/app/admin/DevicePolicyManager;->lockNow", "match_mode": "substring", "bucket": "device_admin", "severity": 0.7, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
        {"ttp_id": "TTP-SILENT-INSTALL", "signal_type": "permission", "match_value": "android.permission.REQUEST_INSTALL_PACKAGES", "match_mode": "exact", "bucket": "install", "severity": 0.45, "requires_context": True, "source": "CERT-In / OWASP MASVS", "source_reference": "CERT-In mobile banking trojan advisories"},
    ])


def downgrade() -> None:
    op.drop_table("detection_markers")
    op.drop_table("ttps")

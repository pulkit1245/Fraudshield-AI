"""Upload validation: magic-byte APK/ZIP signature + size cap.

An APK is a ZIP archive, so we validate the ZIP local-file-header magic
(`PK\\x03\\x04`, or the empty/spanned variants) rather than trusting the client
Content-Type. We additionally confirm an `AndroidManifest.xml` entry exists so a
plain ZIP can't masquerade as an APK.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import io
import zipfile

from app.core.config import settings

# ZIP local file header signatures.
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


class ValidationError(Exception):
    """Raised when an upload fails a validation rule. Carries an HTTP status."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def check_size(num_bytes: int) -> None:
    """Reject files above the configured cap (→ 413)."""
    if num_bytes <= 0:
        raise ValidationError(422, "Empty upload")
    if num_bytes > settings.MAX_UPLOAD_BYTES:
        cap_mb = settings.MAX_UPLOAD_BYTES // (1024 * 1024)
        raise ValidationError(413, f"File exceeds {cap_mb} MB limit")


def has_zip_magic(header: bytes) -> bool:
    return any(header.startswith(m) for m in _ZIP_MAGICS)


def is_valid_apk(data: bytes) -> bool:
    """True if bytes look like a real APK (valid ZIP containing AndroidManifest.xml)."""
    if not has_zip_magic(data[:4]):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            return "AndroidManifest.xml" in names
    except zipfile.BadZipFile:
        return False


def validate_apk_upload(data: bytes, *, filename: str = "") -> None:
    """Full gate for an uploaded APK. Raises ValidationError on failure.

    - 413 if too large
    - 415 if not a valid APK/ZIP signature or missing AndroidManifest.xml
    """
    check_size(len(data))
    if not has_zip_magic(data[:4]):
        raise ValidationError(415, "Not a valid APK (bad file signature)")
    if not is_valid_apk(data):
        raise ValidationError(415, "Not a valid APK (missing AndroidManifest.xml)")
    if filename and not filename.lower().endswith(".apk"):
        # Non-fatal by spec (magic-byte is authoritative) but worth flagging.
        raise ValidationError(415, "File extension must be .apk")

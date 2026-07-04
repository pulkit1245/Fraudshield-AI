"""Object-storage wrapper for raw APKs and sandbox artifacts.

Primary backend is any S3-compatible bucket (Backblaze B2 / AWS S3) via boto3.
When no storage credentials are configured (local dev / CI) it transparently
falls back to a local-filesystem backend so the upload path still works end to
end without a cloud account.

Public API used by the rest of the backend:
    storage.upload_apk(data, sha256, original_filename) -> storage_key
    storage.get_download_url(storage_key, expires=3600) -> str
    storage.download(storage_key) -> bytes
    storage.delete(storage_key) -> None

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import os
import pathlib
from typing import Protocol

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


class StorageBackend(Protocol):
    def upload_apk(self, data: bytes, sha256: str, original_filename: str) -> str: ...
    def get_download_url(self, key: str, expires: int = 3600) -> str: ...
    def download(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...
    def upload_artifact(self, data: bytes, key: str,
                        content_type: str = "application/octet-stream") -> str: ...


def _object_key(sha256: str, original_filename: str) -> str:
    """Content-addressed key: dedupes identical uploads by hash."""
    safe = pathlib.Path(original_filename).name or "sample.apk"
    return f"apks/{sha256[:2]}/{sha256}/{safe}"


# ── S3-compatible backend ───────────────────────────────────────────────
class S3Storage:
    def __init__(self) -> None:
        import boto3  # imported lazily so local dev needn't have creds

        self._bucket = settings.STORAGE_BUCKET
        self._client = boto3.client(
            "s3",
            aws_access_key_id=settings.STORAGE_KEY,
            aws_secret_access_key=settings.STORAGE_SECRET,
            endpoint_url=settings.STORAGE_ENDPOINT_URL or None,
            region_name=settings.STORAGE_REGION,
        )

    def upload_apk(self, data: bytes, sha256: str, original_filename: str) -> str:
        key = _object_key(sha256, original_filename)
        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=data,
            ContentType="application/vnd.android.package-archive",
            # Defense-in-depth: uploaded samples are never executable objects.
            Metadata={"sha256": sha256},
        )
        log.info("storage.upload", backend="s3", key=key, bytes=len(data))
        return key

    def get_download_url(self, key: str, expires: int = 3600) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )

    def download(self, key: str) -> bytes:
        obj = self._client.get_object(Bucket=self._bucket, Key=key)
        return obj["Body"].read()

    def delete(self, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key)
        log.info("storage.delete", backend="s3", key=key)

    def upload_artifact(self, data: bytes, key: str,
                        content_type: str = "application/octet-stream") -> str:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data,
                                ContentType=content_type)
        log.info("storage.upload_artifact", backend="s3", key=key, bytes=len(data))
        return key


# ── Local filesystem fallback ───────────────────────────────────────────
class LocalStorage:
    def __init__(self, root: str | None = None) -> None:
        self._root = pathlib.Path(root or os.getenv("LOCAL_STORAGE_DIR", "/tmp/fraudshield-storage"))
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> pathlib.Path:
        return self._root / key

    def upload_apk(self, data: bytes, sha256: str, original_filename: str) -> str:
        key = _object_key(sha256, original_filename)
        dest = self._path(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        log.info("storage.upload", backend="local", key=key, bytes=len(data))
        return key

    def get_download_url(self, key: str, expires: int = 3600) -> str:
        # No presigning locally; return a file:// URL for dev tooling.
        return self._path(key).as_uri()

    def download(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete(self, key: str) -> None:
        p = self._path(key)
        if p.exists():
            p.unlink()
        log.info("storage.delete", backend="local", key=key)

    def upload_artifact(self, data: bytes, key: str,
                        content_type: str = "application/octet-stream") -> str:
        dest = self._path(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        log.info("storage.upload_artifact", backend="local", key=key, bytes=len(data))
        return key


def _build_storage() -> StorageBackend:
    if settings.STORAGE_KEY and settings.STORAGE_SECRET:
        try:
            return S3Storage()
        except Exception as exc:  # noqa: BLE001
            log.warning("storage.s3_init_failed", error=str(exc))
    log.info("storage.backend", backend="local")
    return LocalStorage()


# Module-level singleton used across the app.
storage: StorageBackend = _build_storage()

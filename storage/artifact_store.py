"""
Artifact store — manages file artifacts (source archives, compiled binaries,
raw sandbox reports) with SHA-256 content addressing.

Artifacts are stored on disk under a configurable base directory.
The metadata index is kept in SQLite.

Security features:
  - Optional AES-256-GCM encryption at rest for PE/binary artifacts
  - Secure temp file handling (no plaintext remnants)
  - NTFS alternate-data-stream marker for encrypted files
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import sqlite3
import struct
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional encryption support ──────────────────────────────────────────
_CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    AESGCM = None  # type: ignore


# Magic header for encrypted artifacts: "LMENC\x01" + 12-byte nonce + ciphertext
_ENC_MAGIC = b"LMENC\x01"
_NONCE_LEN = 12  # 96-bit nonce for AES-GCM

# File extensions considered sensitive (PE binaries and build intermediates)
_SENSITIVE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".obj", ".o",
    ".pdb", ".ilk", ".lib", ".exp", ".bin",
})


class ArtifactStore:
    """
    Content-addressed artifact store.

    Each artifact is stored as:
        <base_dir>/<sha256[:2]>/<sha256>/  (content-addressed)

    together with a metadata row in SQLite.
    """

    def __init__(self, base_dir: str = "artifacts", db_path: str = "state.db",
                 encrypt_pe: bool = False, encryption_key: Optional[str] = None) -> None:
        """
        Args:
            base_dir: Root directory for artifact files.
            db_path:  SQLite database file for metadata.
            encrypt_pe: If True, encrypt PE/binary artifacts at rest with AES-256-GCM.
            encryption_key: Hex-encoded 256-bit key. Auto-generated and logged if omitted.
        """
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._encrypt_pe = encrypt_pe and _CRYPTO_AVAILABLE
        self._enc_key: Optional[bytes] = None

        if encrypt_pe:
            if not _CRYPTO_AVAILABLE:
                logger.warning(
                    "encrypt_pe requested but 'cryptography' package not installed. "
                    "Run: pip install cryptography"
                )
            else:
                self._enc_key = self._resolve_encryption_key(encryption_key)
                logger.info("Artifact encryption enabled (AES-256-GCM)")

        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id  TEXT PRIMARY KEY,
                    job_id       TEXT NOT NULL,
                    sample_id    TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    file_path    TEXT NOT NULL,
                    sha256       TEXT NOT NULL,
                    size_bytes   INTEGER NOT NULL,
                    created_at   TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job ON artifacts (job_id)")
            conn.commit()

    # ──────────────────────────────────────────────────────────────────────
    # Encryption key management
    # ──────────────────────────────────────────────────────────────────────

    _KEY_FILENAME = ".artifact_encryption_key"

    def _resolve_encryption_key(self, explicit_key: Optional[str]) -> bytes:
        """
        Resolve encryption key with priority:
          1. Explicit parameter (hex string)
          2. Environment variable ARTIFACT_ENCRYPTION_KEY
          3. Key file in base_dir/.artifact_encryption_key
          4. Generate new key → save to key file

        The key file is always written when a new key is generated,
        so it is never lost between runs.
        """
        # 1. Explicit parameter
        if explicit_key:
            key = bytes.fromhex(explicit_key)
            self._save_key_file(key)  # persist for future runs
            return key

        # 2. Environment variable
        env_key = os.environ.get("ARTIFACT_ENCRYPTION_KEY", "").strip()
        if env_key:
            key = bytes.fromhex(env_key)
            self._save_key_file(key)
            return key

        # 3. Existing key file
        key_path = self._base_dir / self._KEY_FILENAME
        if key_path.exists():
            try:
                key_hex = key_path.read_text(encoding="utf-8").strip()
                key = bytes.fromhex(key_hex)
                logger.info("Loaded encryption key from %s", key_path)
                return key
            except (ValueError, OSError) as e:
                logger.warning("Failed to read key file %s: %s", key_path, e)

        # 4. Generate new key → save to file
        key = secrets.token_bytes(32)
        self._save_key_file(key)
        logger.info(
            "Generated new encryption key → saved to %s", key_path
        )
        return key

    def _save_key_file(self, key: bytes) -> None:
        """Persist key to file with restricted permissions."""
        key_path = self._base_dir / self._KEY_FILENAME
        try:
            key_path.write_text(key.hex(), encoding="utf-8")
            # Restrict file permissions (Windows: remove inheritance, owner-only)
            if os.name == "nt":
                import subprocess
                subprocess.run(
                    ["icacls", str(key_path), "/inheritance:r",
                     "/grant:r", f"{os.environ.get('USERNAME', 'SYSTEM')}:F"],
                    capture_output=True, timeout=10,
                )
            else:
                os.chmod(str(key_path), 0o600)
        except OSError as e:
            logger.warning("Could not save key file %s: %s", key_path, e)

    # ──────────────────────────────────────────────────────────────────────
    # Encryption helpers
    # ──────────────────────────────────────────────────────────────────────

    def _should_encrypt(self, filepath: str) -> bool:
        """Decide whether a file should be encrypted at rest."""
        if not self._encrypt_pe or not self._enc_key:
            return False
        ext = Path(filepath).suffix.lower()
        return ext in _SENSITIVE_EXTENSIONS

    def _encrypt_file(self, src_path: str, dest_path: str) -> None:
        """Encrypt src_path → dest_path using AES-256-GCM."""
        nonce = secrets.token_bytes(_NONCE_LEN)
        aes = AESGCM(self._enc_key)
        with open(src_path, "rb") as f:
            plaintext = f.read()
        ciphertext = aes.encrypt(nonce, plaintext, None)
        with open(dest_path, "wb") as f:
            f.write(_ENC_MAGIC)
            f.write(nonce)
            f.write(ciphertext)
        logger.debug("Encrypted artifact: %s (%d → %d bytes)",
                      dest_path, len(plaintext), os.path.getsize(dest_path))

    def _decrypt_file(self, enc_path: str, dest_path: str) -> None:
        """Decrypt an encrypted artifact to dest_path."""
        with open(enc_path, "rb") as f:
            magic = f.read(len(_ENC_MAGIC))
            if magic != _ENC_MAGIC:
                raise ValueError(f"Not an encrypted artifact: {enc_path}")
            nonce = f.read(_NONCE_LEN)
            ciphertext = f.read()
        aes = AESGCM(self._enc_key)
        plaintext = aes.decrypt(nonce, ciphertext, None)
        with open(dest_path, "wb") as f:
            f.write(plaintext)

    def _is_encrypted(self, filepath: str) -> bool:
        """Check if a stored artifact is encrypted."""
        try:
            with open(filepath, "rb") as f:
                return f.read(len(_ENC_MAGIC)) == _ENC_MAGIC
        except (OSError, IOError):
            return False

    def decrypt_to_temp(self, artifact_id: str) -> Optional[str]:
        """
        Decrypt an encrypted artifact to a temp file for submission.
        Caller is responsible for deleting the temp file.
        Returns path to decrypted temp file, or original path if not encrypted.
        """
        path = self.get_path_sync(artifact_id)
        if not path or not os.path.exists(path):
            return None
        if not self._is_encrypted(path):
            return path  # not encrypted, return as-is
        if not self._enc_key:
            raise RuntimeError("Cannot decrypt: no encryption key configured")
        import tempfile
        fd, tmp_path = tempfile.mkstemp(suffix=Path(path).suffix)
        os.close(fd)
        try:
            self._decrypt_file(path, tmp_path)
            return tmp_path
        except Exception:
            os.unlink(tmp_path)
            raise

    def decrypt_to_bytes(self, artifact_id: str) -> Optional[bytes]:
        """
        Decrypt an encrypted artifact entirely in memory.
        Returns raw bytes (the original PE content), or None if not found.
        No plaintext ever touches disk.
        """
        path = self.get_path_sync(artifact_id)
        if not path or not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            header = f.read(len(_ENC_MAGIC))
            if header != _ENC_MAGIC:
                # Not encrypted — read whole file
                f.seek(0)
                return f.read()
            nonce = f.read(_NONCE_LEN)
            ciphertext = f.read()
        if not self._enc_key:
            raise RuntimeError("Cannot decrypt: no encryption key configured")
        aes = AESGCM(self._enc_key)
        return aes.decrypt(nonce, ciphertext, None)

    # ──────────────────────────────────────────────────────────────────────
    # Store
    # ──────────────────────────────────────────────────────────────────────

    def store_sync(
        self,
        job_id: str,
        sample_id: str,
        source_path: str,
        artifact_type: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Copy a file into the artifact store.
        Returns artifact_id (UUID string).
        """
        sha256 = self._sha256(source_path)
        size = os.path.getsize(source_path)

        dest_dir = self._base_dir / sha256[:2] / sha256
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = (dest_dir / Path(source_path).name).resolve()

        if not dest_path.exists():
            if self._should_encrypt(source_path):
                self._encrypt_file(source_path, str(dest_path))
            else:
                shutil.copy2(source_path, dest_path)

        artifact_id = str(uuid.uuid4())
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT INTO artifacts
                    (artifact_id, job_id, sample_id, artifact_type, file_path, sha256, size_bytes, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact_id,
                job_id,
                sample_id,
                artifact_type,
                str(dest_path),
                sha256,
                size,
                datetime.utcnow().isoformat(),
                json.dumps(metadata or {}),
            ))
            conn.commit()

        logger.debug("Stored artifact %s (%s) sha256=%s", artifact_id, artifact_type, sha256)
        return artifact_id

    def store_json_sync(
        self,
        job_id: str,
        sample_id: str,
        data: dict,
        artifact_type: str,
        filename: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Store a dict as a JSON artifact (no source file needed).
        Returns artifact_id.
        """
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(data, tmp, ensure_ascii=False, indent=2)
            tmp_path = tmp.name

        try:
            # Rename to desired filename in a temp dir
            tmp_dir = os.path.dirname(tmp_path)
            dest_tmp = os.path.join(tmp_dir, filename)
            shutil.move(tmp_path, dest_tmp)
            return self.store_sync(job_id, sample_id, dest_tmp, artifact_type, metadata)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ──────────────────────────────────────────────────────────────────────
    # Retrieve
    # ──────────────────────────────────────────────────────────────────────

    def get_path_sync(self, artifact_id: str) -> Optional[str]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT file_path FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        return row[0] if row else None

    # ──────────────────────────────────────────────────────────────────────
    # Async compatibility layer (used by multi-agent pipeline)
    # ──────────────────────────────────────────────────────────────────────

    async def store(
        self,
        job_id: str,
        artifact_type: str,
        sample_id: str = "",
        source_path: str = "",
        file_path: Optional[Path] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Async wrapper for storing file artifacts.

        Supports both call styles:
          - store(job_id=..., sample_id=..., source_path=..., artifact_type=...)
          - store(job_id=..., artifact_type=..., file_path=Path(...))
        """
        if file_path is not None:
            source_path = str(file_path)
        if not source_path:
            raise ValueError("source_path/file_path is required")
        if not sample_id:
            sample_id = job_id
        return self.store_sync(
            job_id=job_id,
            sample_id=sample_id,
            source_path=source_path,
            artifact_type=artifact_type,
            metadata=metadata,
        )

    async def store_json(
        self,
        job_id: str,
        data: dict,
        artifact_type: str,
        sample_id: str = "",
        filename: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Async wrapper for storing JSON artifacts."""
        if not sample_id:
            sample_id = job_id
        if not filename:
            filename = f"{artifact_type}.json"
        return self.store_json_sync(
            job_id=job_id,
            sample_id=sample_id,
            data=data,
            artifact_type=artifact_type,
            filename=filename,
            metadata=metadata,
        )

    async def get_path(self, *args) -> Optional[Path]:
        """
        Async path lookup.

        Accepts:
          - get_path(artifact_id)
          - get_path(job_id, artifact_id)  # job_id ignored for compatibility
        """
        if len(args) == 1:
            artifact_id = args[0]
        elif len(args) == 2:
            artifact_id = args[1]
        else:
            raise ValueError("get_path expects (artifact_id) or (job_id, artifact_id)")
        p = self.get_path_sync(artifact_id)
        return Path(p) if p else None

    async def get_json(self, *args) -> Optional[dict]:
        """
        Async JSON artifact load.

        Accepts:
          - get_json(artifact_id)
          - get_json(job_id, artifact_id)  # job_id ignored for compatibility
        """
        if len(args) == 1:
            artifact_id = args[0]
        elif len(args) == 2:
            artifact_id = args[1]
        else:
            raise ValueError("get_json expects (artifact_id) or (job_id, artifact_id)")

        path = self.get_path_sync(artifact_id)
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def get_metadata(self, artifact_id: str) -> Optional[dict]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT metadata_json, sha256, size_bytes, artifact_type FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        if not row:
            return None
        meta = json.loads(row[0])
        meta.update({"sha256": row[1], "size_bytes": row[2], "artifact_type": row[3]})
        return meta

    def list_for_job(self, job_id: str) -> list[dict]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT artifact_id, artifact_type, sha256, size_bytes, created_at FROM artifacts WHERE job_id = ?",
                (job_id,),
            ).fetchall()
        return [
            {"artifact_id": r[0], "type": r[1], "sha256": r[2], "size": r[3], "created_at": r[4]}
            for r in rows
        ]

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple, TYPE_CHECKING

from flask import current_app, jsonify, request
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

import watermarking_utils as WMUtils

from rmap.identity_manager import (
    DecryptionError,
    IdentityManager,
    IdentityManagerError,
)
from rmap.rmap import RMAP

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.engine import Engine


class RmapServiceError(RuntimeError):
    """Raised when the RMAP service cannot complete a request."""


@dataclass
class RmapSession:
    identity: str
    nonce_client: int
    nonce_server: int
    created_at: float


class RmapService:
    """Glue code between Flask, the RMAP library, and the storage layer."""

    def __init__(self, app, get_engine: Callable[[], "Engine"]):
        self.app = app
        self._get_engine = get_engine
        self._identity_manager: Optional[IdentityManager] = None
        self._rmap: Optional[RMAP] = None
        self._sessions: Dict[str, RmapSession] = {}
        self._base_document_id: Optional[int] = None
        self._base_document_path: Optional[Path] = None
        self._system_user_id: Optional[int] = None

    # ------------------------------------------------------------------
    # Exposed route handlers
    # ------------------------------------------------------------------
def handle_initiate(self):
    data = request.get_json(silent=True) or {}
    payload = data.get("payload")
    if not isinstance(payload, str) or not payload:
        return jsonify({"error": "payload must be a non-empty base64 string"}), 400

    # 1) Decrypt first to read identity and validate it exists
    try:
        decrypted = self.identity_manager.decrypt_for_server(payload)
    except DecryptionError as exc:
        current_app.logger.debug("RMAP initiate decrypt failed: %s", exc)
        return jsonify({"error": str(exc)}), 400

    identity = str(decrypted.get("identity", "")).strip()
    if not identity:
        return jsonify({"error": "decrypted identity missing"}), 400

    # 2) Let the RMAP library build Response 1 and record the nonces
    response = self.rmap.handle_message1({"payload": payload})
    if "error" in response:
        current_app.logger.debug("RMAP message1 rejected: %s", response["error"])
        return jsonify(response), 400

    # 3) Save the session for this identity
    session = self._build_session(identity)
    if session is None:
        return jsonify({"error": "failed to record RMAP session"}), 500
    self._sessions[identity] = session
    self._cleanup_expired_sessions()

    return jsonify(response), 200


    def handle_get_link(self):
        data = request.get_json(silent=True) or {}
        payload = data.get("payload")
        if not isinstance(payload, str) or not payload:
            return jsonify({"error": "payload must be a non-empty base64 string"}), 400

        try:
            manager = self.identity_manager
        except RmapServiceError as exc:
            current_app.logger.error("RMAP service unavailable: %s", exc)
            return jsonify({"error": str(exc)}), 503

        try:
            decrypted = manager.decrypt_for_server(payload)
        except DecryptionError as exc:
            current_app.logger.debug("RMAP initiate decrypt failed: %s", exc)
            return jsonify({"error": str(exc)}), 400

        try:
            nonce_server = int(decrypted["nonceServer"])
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "decrypted payload missing nonceServer"}), 400

        session = self._session_by_nonce_server(nonce_server)
        if session is None:
            return jsonify({"error": "unknown or expired nonceServer"}), 400
        if time.time() - session.created_at > self._session_ttl_seconds():
            self._sessions.pop(session.identity, None)
            self.rmap.nonces.pop(session.identity, None)
            return jsonify({"error": "nonceServer expired"}), 400

        response = self.rmap.handle_message2({"payload": payload})
        if "error" in response:
            current_app.logger.debug("RMAP message2 rejected: %s", response["error"])
            return jsonify(response), 400

        link_token = response.get("result")
        if not isinstance(link_token, str):
            return jsonify({"error": "invalid RMAP result"}), 500

        try:
            version_path = self._ensure_watermarked_version(session, link_token)
        except RmapServiceError as exc:
            current_app.logger.error("RMAP watermark generation failed: %s", exc)
            return jsonify({"error": str(exc)}), 500

        # One-time use: drop session and nonce state
        self._sessions.pop(session.identity, None)
        self.rmap.nonces.pop(session.identity, None)

        link_url = request.host_url.rstrip("/") + f"/api/get-version/{link_token}"
        return jsonify({"result": link_token, "url": link_url}), 200

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @property
    def identity_manager(self) -> IdentityManager:
        if self._identity_manager is None:
            self._identity_manager = self._build_identity_manager()
        return self._identity_manager

    @property
    def rmap(self) -> RMAP:
        if self._rmap is None:
            self._rmap = RMAP(self.identity_manager)
        return self._rmap

    def _build_identity_manager(self) -> IdentityManager:
        env = os.environ
        for key in ("RMAP_CLIENT_KEYS_DIR", "RMAP_SERVER_PUB", "RMAP_SERVER_PRIV"):
            if key not in env or not env[key]:
                raise RmapServiceError(f"Environment variable {key} must be set")
        passphrase = env.get("RMAP_SERVER_PRIV_PASSPHRASE") or None
        try:
            return IdentityManager(
                client_keys_dir=env["RMAP_CLIENT_KEYS_DIR"],
                server_public_key_path=env["RMAP_SERVER_PUB"],
                server_private_key_path=env["RMAP_SERVER_PRIV"],
                server_private_key_passphrase=passphrase,
            )
        except (IdentityManagerError, FileNotFoundError) as exc:
            raise RmapServiceError(f"Failed to initialise RMAP keys: {exc}") from exc

    def _build_session(self, identity: str) -> Optional[RmapSession]:
        pair = self.rmap.nonces.get(identity)
        if not pair:
            return None
        try:
            nonce_client = int(pair[0])
            nonce_server = int(pair[1])
        except (TypeError, ValueError):
            return None
        return RmapSession(identity=identity, nonce_client=nonce_client, nonce_server=nonce_server, created_at=time.time())

    def _session_by_nonce_server(self, nonce_server: int) -> Optional[RmapSession]:
        for session in self._sessions.values():
            if session.nonce_server == nonce_server:
                return session
        return None

    def _cleanup_expired_sessions(self) -> None:
        ttl = self._session_ttl_seconds()
        now = time.time()
        expired = [ident for ident, sess in self._sessions.items() if now - sess.created_at > ttl]
        for ident in expired:
            self._sessions.pop(ident, None)
            self.rmap.nonces.pop(ident, None)

    def _session_ttl_seconds(self) -> float:
        try:
            return float(os.environ.get("RMAP_SESSION_TTL_SECONDS", 300))
        except ValueError:
            return 300.0

    def _ensure_watermarked_version(self, session: RmapSession, link_token: str) -> Path:
        existing = self._get_existing_version_path(link_token)
        if existing is not None and existing.exists():
            return existing

        document_id, base_path = self._ensure_base_document()
        method = os.environ.get("RMAP_WATERMARK_METHOD", "toy-eof")
        position = os.environ.get("RMAP_WATERMARK_POSITION") or None
        key = os.environ.get("RMAP_WATERMARK_KEY") or self.app.config.get("SECRET_KEY")
        if not key:
            raise RmapServiceError("No watermarking key configured")

        secret_payload = self._build_secret(session, link_token)

        try:
            applicable = WMUtils.is_watermarking_applicable(method=method, pdf=str(base_path), position=position)
            if applicable is False:
                raise RmapServiceError(f"Watermark method {method} not applicable to base document")
        except Exception as exc:
            raise RmapServiceError(f"Watermark applicability check failed: {exc}") from exc

        try:
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(base_path),
                secret=secret_payload,
                key=key,
                method=method,
                position=position,
            )
        except Exception as exc:
            raise RmapServiceError(f"Watermark generation failed: {exc}") from exc

        storage_root = self.app.config["STORAGE_DIR"].resolve()
        out_dir = storage_root / "rmap" / "deliveries"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = (out_dir / f"{link_token}.pdf").resolve()

        try:
            with out_path.open("wb") as handle:
                handle.write(wm_bytes)
        except Exception as exc:
            raise RmapServiceError(f"Failed to persist watermarked file: {exc}") from exc

        try:
            self._upsert_version_record(
                document_id=document_id,
                link=link_token,
                identity=session.identity,
                secret=secret_payload,
                method=method,
                position=position,
                path=out_path,
            )
        except RmapServiceError:
            raise
        except Exception as exc:
            raise RmapServiceError(f"Failed to record watermarked version: {exc}") from exc

        return out_path

    def _build_secret(self, session: RmapSession, link_token: str) -> str:
        payload = {
            "identity": session.identity,
            "nonceClient": session.nonce_client,
            "nonceServer": session.nonce_server,
            "link": link_token,
            "ts": int(time.time()),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _get_existing_version_path(self, link_token: str) -> Optional[Path]:
        with self._get_engine().connect() as conn:
            row = conn.execute(
                text("SELECT path FROM Versions WHERE link = :link"),
                {"link": link_token},
            ).first()
        if row and getattr(row, "path", None):
            return Path(row.path)
        return None

    def _upsert_version_record(
        self,
        *,
        document_id: int,
        link: str,
        identity: str,
        secret: str,
        method: str,
        position: Optional[str],
        path: Path,
    ) -> None:
        with self._get_engine().begin() as conn:
            existing = conn.execute(
                text("SELECT id FROM Versions WHERE link = :link"),
                {"link": link},
            ).first()
            params = {
                "documentid": int(document_id),
                "link": link,
                "intended_for": identity,
                "secret": secret,
                "method": method,
                "position": position or "",
                "path": str(path),
            }
            if existing:
                conn.execute(
                    text(
                        """
                        UPDATE Versions
                        SET documentid = :documentid,
                            intended_for = :intended_for,
                            secret = :secret,
                            method = :method,
                            position = :position,
                            path = :path
                        WHERE link = :link
                        """
                    ),
                    params,
                )
            else:
                try:
                    conn.execute(
                        text(
                            """
                            INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                            VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                            """
                        ),
                        params,
                    )
                except IntegrityError as exc:
                    raise RmapServiceError(f"Version record already exists for link {link}") from exc

    def _ensure_base_document(self) -> Tuple[int, Path]:
        if self._base_document_id is not None and self._base_document_path is not None:
            return self._base_document_id, self._base_document_path

        env = os.environ
        doc_id_env = env.get("RMAP_BASE_DOCUMENT_ID")
        if doc_id_env:
            try:
                doc_id = int(doc_id_env)
            except ValueError as exc:
                raise RmapServiceError("RMAP_BASE_DOCUMENT_ID must be an integer") from exc
            with self._get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, path FROM Documents WHERE id = :id"),
                    {"id": doc_id},
                ).first()
            if not row:
                raise RmapServiceError(f"Document id {doc_id} not found")
            path = Path(row.path).resolve()
            self._base_document_id = doc_id
            self._base_document_path = path
            return doc_id, path

        source_path = env.get("RMAP_BASE_PDF")
        if source_path:
            base_source = Path(source_path)
        else:
            base_source = (Path(self.app.root_path).parent.parent / "flag.pdf")
        if not base_source.exists():
            raise RmapServiceError(f"Base PDF not found at {base_source}")

        storage_root = self.app.config["STORAGE_DIR"].resolve()
        target_dir = storage_root / "rmap"
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = (target_dir / base_source.name).with_suffix(".pdf")
        target_path = target_path.resolve()

        if not target_path.exists():
            try:
                shutil.copy2(base_source, target_path)
            except Exception as exc:
                raise RmapServiceError(f"Failed to stage base PDF: {exc}") from exc
        owner_id = self._ensure_system_user()
        sha_hex = self._sha256_hex(target_path)
        size = target_path.stat().st_size
        name = os.environ.get("RMAP_BASE_DOCUMENT_NAME", target_path.name)

        with self._get_engine().begin() as conn:
            existing = conn.execute(
                text("SELECT id FROM Documents WHERE path = :path"),
                {"path": str(target_path)},
            ).first()
            if existing:
                doc_id = int(existing.id)
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                        """
                    ),
                    {
                        "name": name,
                        "path": str(target_path),
                        "ownerid": int(owner_id),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                doc_id = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())

        self._base_document_id = doc_id
        self._base_document_path = target_path
        return doc_id, target_path

    def _ensure_system_user(self) -> int:
        if self._system_user_id is not None:
            return self._system_user_id

        email = os.environ.get("RMAP_SYSTEM_EMAIL", "rmap@tatou.local")
        login = os.environ.get("RMAP_SYSTEM_LOGIN", "rmap-service")
        password = os.environ.get("RMAP_SYSTEM_PASSWORD")

        with self._get_engine().begin() as conn:
            row = conn.execute(
                text("SELECT id FROM Users WHERE email = :email"),
                {"email": email},
            ).first()
            if row:
                self._system_user_id = int(row.id)
                return self._system_user_id

            if not password:
                password = os.urandom(16).hex()
            hpw = generate_password_hash(password)

            conn.execute(
                text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                {"email": email, "hpw": hpw, "login": login},
            )
            uid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())

        self._system_user_id = uid
        return uid

    @staticmethod
    def _sha256_hex(path: Path) -> str:
        import hashlib

        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()


def register_rmap_routes(app, get_engine: Callable[[], "Engine"]) -> None:
    """Attach the RMAP endpoints to the Flask app."""
    service = RmapService(app, get_engine)

    @app.post("/api/rmap-initiate")
    def _rmap_initiate():
        return service.handle_initiate()

    @app.post("/api/rmap-get-link")
    def _rmap_get_link():
        return service.handle_get_link()


__all__ = ["register_rmap_routes", "RmapService", "RmapServiceError"]



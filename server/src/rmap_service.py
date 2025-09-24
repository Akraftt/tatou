from __future__ import annotations
import os
from pathlib import Path
from flask import jsonify, request, current_app
from werkzeug.utils import secure_filename
from sqlalchemy import text

from rmap.identity_manager import IdentityManager, IdentityManagerError, DecryptionError, EncryptionError
from rmap.rmap import RMAP, ValidationError

import watermarking_utils as WM

def _read_payload_b64() -> str:
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        p = data.get("payload")
        if isinstance(p, str) and p:
            return p
    raw = (request.get_data(as_text=True) or "").strip()
    if raw:
        return raw
    raise ValidationError("'payload' must be a non-empty base64 string")

def register_rmap_routes(app, get_engine):
    """Attach /api/rmap-initiate and /api/rmap-get-link to the Flask app."""
    try:
        im = IdentityManager(
            client_keys_dir=os.environ["RMAP_CLIENT_KEYS_DIR"],
            server_public_key_path=os.environ["RMAP_SERVER_PUB"],
            server_private_key_path=os.environ["RMAP_SERVER_PRIV"],
            server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE") or None,
        )
        rmap = RMAP(im)
    except Exception as exc:
        current_app.logger.error("Failed to initialize RMAP: %s", exc)
        im = None
        rmap = None

    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        if rmap is None:
            return jsonify({"error": "RMAP service unavailable"}), 503
        try:
            payload = _read_payload_b64()
            resp = rmap.handle_message1({"payload": payload})
            return (jsonify(resp), 200) if "payload" in resp else (jsonify(resp), 400)
        except (ValidationError, DecryptionError, EncryptionError, IdentityManagerError) as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            current_app.logger.exception("rmap-initiate failed")
            return jsonify({"error": f"internal error: {exc}"}), 500

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        """
        Accepts Message 2; creates a watermarked PDF and DB row; returns {"result":"<32-hex>"}.
        """
        if rmap is None or im is None:
            return jsonify({"error": "RMAP service unavailable"}), 503

        src_doc_id = os.environ.get("RMAP_SOURCE_DOC_ID")
        wm_key = os.environ.get("RMAP_WM_KEY")
        best_method = os.environ.get("RMAP_METHOD", "toy-eof")
        if not src_doc_id or not wm_key:
            return jsonify({"error": "server misconfigured: set RMAP_SOURCE_DOC_ID and RMAP_WM_KEY"}), 503

        try:
            payload = _read_payload_b64()

            # Decrypt to get nonceServer and locate identity
            obj = im.decrypt_for_server(payload)
            if not isinstance(obj, dict) or "nonceServer" not in obj:
                return jsonify({"error": "invalid payload: missing nonceServer"}), 400
            nonce_server = int(obj["nonceServer"])

            identity = None
            for ident, pair in rmap.nonces.items():
                if len(pair) == 2 and int(pair[1]) == nonce_server:
                    identity = ident
                    break
            if not identity:
                return jsonify({"error": "nonceServer does not match any pending session"}), 400

            # Let the library produce the 32-hex session secret
            final = rmap.handle_message2({"payload": payload})
            if "result" not in final:
                return jsonify(final), 400
            link_token = final["result"]

            # Lookup source document path
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, path FROM Documents WHERE id = :id LIMIT 1"),
                    {"id": int(src_doc_id)},
                ).first()
            if not row:
                return jsonify({"error": f"document id {src_doc_id} not found"}), 404

            storage_root = Path(app.config["STORAGE_DIR"]).resolve()
            src_path = Path(row.path)
            if not src_path.is_absolute():
                src_path = storage_root / src_path
            src_path = src_path.resolve()
            try:
                src_path.relative_to(storage_root)
            except Exception:
                return jsonify({"error": "document path invalid"}), 500
            if not src_path.exists():
                return jsonify({"error": "file missing on disk"}), 410

            # Watermark secret binds identity + session
            secret = f"identity={identity};session={link_token}"
            wm_bytes = WM.apply_watermark(
                method=best_method,
                pdf=str(src_path),
                secret=secret,
                key=str(wm_key),
                position=None,
            )

            dest_dir = src_path.parent / "watermarks"
            dest_dir.mkdir(parents=True, exist_ok=True)
            base_name = Path(row.name or src_path.name).stem
            intended_slug = secure_filename(identity)
            dest_path = dest_dir / f"{base_name}__{intended_slug}.pdf"
            with dest_path.open("wb") as fh:
                fh.write(wm_bytes)

            # Persist in Versions (link is the session secret)
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": int(row.id),
                        "link": link_token,
                        "intended_for": identity,
                        "secret": secret,
                        "method": best_method,
                        "position": "",
                        "path": str(dest_path),
                    },
                )

            return jsonify({"result": link_token}), 200

        except (ValidationError, DecryptionError) as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            current_app.logger.exception("rmap-get-link failed")
            return jsonify({"error": f"internal error: {exc}"}), 500

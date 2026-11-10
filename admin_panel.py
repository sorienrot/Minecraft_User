"""Panel administrativo para registrar clientes y sus callbacks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import ipaddress
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response


ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if (
    not ADMIN_USERNAME
    or len(ADMIN_PASSWORD) < 16
    or ADMIN_PASSWORD.lower().startswith(("replace-", "change-me"))
):
    raise RuntimeError(
        "Configura ADMIN_USERNAME y ADMIN_PASSWORD (mínimo 16 caracteres) en .env."
    )
if len(SESSION_SECRET) < 32 or SESSION_SECRET.lower().startswith("replace-"):
    raise RuntimeError("SESSION_SECRET debe ser una clave aleatoria de 32 caracteres o más para proteger TOTP.")
_totp_fernet_key = base64.urlsafe_b64encode(
    hashlib.sha256(("minecraft-admin-totp-v1:" + SESSION_SECRET).encode("utf-8")).digest()
)
_totp_cipher = Fernet(_totp_fernet_key)

DB_PATH = Path(os.getenv("CLIENTS_DB_PATH", str(Path(__file__).with_name("clients.sqlite3"))))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
router = APIRouter()

_login_failures: dict[str, tuple[float, int]] = {}
_login_lock = threading.Lock()
_PBKDF2_ROUNDS = 310_000


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                secret_salt TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS callbacks (
                callback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
                uri TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(client_id, uri)
            );
            CREATE TABLE IF NOT EXISTS client_tokens (
                token_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
                callback_uri TEXT NOT NULL,
                client_state TEXT NOT NULL,
                profile_name TEXT NOT NULL,
                profile_uuid TEXT NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL
            );
            CREATE TABLE IF NOT EXISTS admin_totp (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                secret_ciphertext TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                last_counter INTEGER NOT NULL DEFAULT -1,
                created_at TEXT NOT NULL
            );
            """
        )
        totp_columns = {
            column["name"]
            for column in db.execute("PRAGMA table_info(admin_totp)").fetchall()
        }
        if "last_counter" not in totp_columns:
            db.execute(
                "ALTER TABLE admin_totp ADD COLUMN last_counter INTEGER NOT NULL DEFAULT -1"
            )


initialize_database()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_client_secret(secret: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return salt.hex(), digest.hex()


def verify_client_secret(secret: str, salt_hex: str, digest_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, actual = hash_client_secret(secret, salt)
    return hmac.compare_digest(actual, digest_hex)


def totp_status() -> bool:
    with database() as db:
        row = db.execute("SELECT enabled FROM admin_totp WHERE singleton=1").fetchone()
    return bool(row and row["enabled"])


def decrypt_totp_secret(ciphertext: str) -> str:
    try:
        return _totp_cipher.decrypt(ciphertext.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeError) as exc:
        raise RuntimeError(
            "No se pudo descifrar el TOTP. Mantén el SESSION_SECRET original o restablece el enrolamiento TOTP."
        ) from exc


def get_or_create_totp_secret() -> str:
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT secret_ciphertext FROM admin_totp WHERE singleton=1"
        ).fetchone()
        if row:
            ciphertext = row["secret_ciphertext"]
        else:
            secret = pyotp.random_base32()
            ciphertext = _totp_cipher.encrypt(secret.encode("ascii")).decode("ascii")
            db.execute(
                "INSERT INTO admin_totp(singleton,secret_ciphertext,enabled,created_at) VALUES(1,?,0,?)",
                (ciphertext, now_iso()),
            )
            return secret
    return decrypt_totp_secret(ciphertext)


def verify_totp(code: str) -> bool:
    if not code.isdigit() or len(code) != 6:
        return False
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT secret_ciphertext,last_counter FROM admin_totp WHERE singleton=1"
        ).fetchone()
        if not row:
            return False
        secret = decrypt_totp_secret(row["secret_ciphertext"])
        totp = pyotp.TOTP(secret)
        current_counter = int(time.time() // totp.interval)
        for counter in (current_counter - 1, current_counter, current_counter + 1):
            if counter > row["last_counter"] and hmac.compare_digest(totp.generate_otp(counter), code):
                db.execute(
                    "UPDATE admin_totp SET last_counter=? WHERE singleton=1",
                    (counter,),
                )
                return True
        return False


def validate_callback_uri(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048 or any(ch.isspace() for ch in value):
        raise ValueError("Introduce una URI completa y sin espacios.")
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("La callback debe ser una URI absoluta HTTPS.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("La callback no puede contener credenciales ni fragmento (#).")
    if parsed.query:
        raise ValueError("Registra la ruta de callback sin parámetros de consulta.")

    hostname = parsed.hostname.lower().rstrip(".")
    if parsed.scheme == "http":
        if hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("HTTP solo se permite en localhost para desarrollo; usa HTTPS en otros hosts.")
    else:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("No se admiten IP privadas o locales como callback HTTPS.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("La URI contiene un puerto no válido.") from exc
    return value


def secure_page(body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        body,
        status_code=status_code,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        },
    )


def form_html(title: str, content: str) -> str:
    return (
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>"
        "body{font:16px system-ui;max-width:980px;margin:3rem auto;padding:0 1rem;color:#172033;background:#f5f7fb}"
        "main{background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 24px #15244218}"
        "input,textarea,button{font:inherit;padding:.65rem;margin:.25rem 0}input,textarea{width:min(100%,38rem);box-sizing:border-box}"
        "textarea{min-height:4rem}button{cursor:pointer}table{border-collapse:collapse;width:100%;margin:1rem 0}td,th{border-bottom:1px solid #ddd;padding:.6rem;text-align:left;vertical-align:top}"
        ".notice{padding:1rem;background:#eef5ff;border-left:4px solid #1673d1;overflow-wrap:anywhere}"
        ".error{padding:1rem;background:#fff1f0;border-left:4px solid #c62828}form.inline{display:inline}code{overflow-wrap:anywhere}"
        "</style></head><body><main>" + content + "</main></body></html>"
    )


def csrf_token(request: Request) -> str:
    token = request.session.get("admin_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["admin_csrf"] = token
    return token


def is_admin(request: Request) -> bool:
    authenticated_at = request.session.get("admin_mfa_at")
    return (
        request.session.get("admin_authenticated") is True
        and isinstance(authenticated_at, (int, float))
        and time.time() - authenticated_at <= 1800
    )


async def read_form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8", errors="replace")
    return {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}


def csrf_valid(request: Request, form: dict[str, str]) -> bool:
    expected = request.session.get("admin_csrf", "")
    actual = form.get("csrf_token", "")
    return bool(expected and actual) and hmac.compare_digest(expected, actual)


def login_page(request: Request, message: str = "", status: int = 200) -> HTMLResponse:
    error = f"<p class='error'>{html.escape(message)}</p>" if message else ""
    csrf = html.escape(csrf_token(request), quote=True)
    content = (
        "<h1>Administración de clientes</h1>"
        "<p>Acceso restringido. Las credenciales se configuran en el servidor.</p>"
        f"{error}<form method='post' action='/admin/login'>"
        f"<input type='hidden' name='csrf_token' value='{csrf}'>"
        "<label>Usuario<br><input name='username' autocomplete='username' required></label><br>"
        "<label>Contraseña<br><input type='password' name='password' autocomplete='current-password' required></label><br>"
        "<button type='submit'>Iniciar sesión</button></form>"
    )
    return secure_page(form_html("Administración", content), status)


def admin_mfa_page(request: Request, message: str = "", status: int = 200) -> HTMLResponse:
    error = f"<p class='error'>{html.escape(message)}</p>" if message else ""
    csrf = html.escape(csrf_token(request), quote=True)
    content = (
        "<h1>Verificación en dos pasos</h1>"
        "<p>Introduce el código de 6 dígitos de tu app Authenticator.</p>"
        f"{error}<form method='post' action='/admin/mfa'>"
        f"<input type='hidden' name='csrf_token' value='{csrf}'>"
        "<label>Código TOTP<br><input name='code' inputmode='numeric' autocomplete='one-time-code' "
        "pattern='[0-9]{6}' maxlength='6' required autofocus></label><br>"
        "<button type='submit'>Verificar</button></form>"
    )
    return secure_page(form_html("Verificación TOTP", content), status)


def totp_setup_page(request: Request, message: str = "", status: int = 200) -> HTMLResponse:
    error = f"<p class='error'>{html.escape(message)}</p>" if message else ""
    try:
        secret = get_or_create_totp_secret()
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=ADMIN_USERNAME,
            issuer_name="Minecraft Profile API Admin",
        )
        image_buffer = io.BytesIO()
        qrcode.make(uri).save(image_buffer, format="PNG")
        qr_data = base64.b64encode(image_buffer.getvalue()).decode("ascii")
    except RuntimeError as exc:
        return secure_page(
            form_html("Configurar TOTP", f"<h1>No se pudo preparar el segundo factor</h1><p>{html.escape(str(exc))}</p>"),
            500,
        )
    csrf = html.escape(csrf_token(request), quote=True)
    content = (
        "<h1>Configura el segundo factor</h1>"
        "<p>Escanea el QR con Microsoft Authenticator, Google Authenticator u otra app TOTP. "
        "Si no puedes escanearlo, añade manualmente este secreto:</p>"
        f"<p><code>{html.escape(secret)}</code></p>"
        f"<p><img alt='Código QR TOTP' width='220' height='220' src='data:image/png;base64,{qr_data}'></p>"
        "<p>Introduce el código actual para confirmar el enrolamiento.</p>"
        f"{error}<form method='post' action='/admin/setup-mfa'>"
        f"<input type='hidden' name='csrf_token' value='{csrf}'>"
        "<label>Código TOTP<br><input name='code' inputmode='numeric' autocomplete='one-time-code' "
        "pattern='[0-9]{6}' maxlength='6' required autofocus></label><br>"
        "<button type='submit'>Confirmar y activar</button></form>"
    )
    return secure_page(form_html("Configurar TOTP", content), status)


def establish_admin_session(request: Request) -> None:
    request.session.clear()
    request.session["admin_authenticated"] = True
    request.session["admin_mfa_at"] = time.time()
    request.session["admin_csrf"] = secrets.token_urlsafe(32)


def admin_redirect() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=303)


def dashboard(request: Request, notice: str = "", one_time_secret: tuple[str, str] | None = None) -> HTMLResponse:
    with database() as db:
        clients = db.execute(
            "SELECT client_id,name,created_at,revoked_at FROM clients ORDER BY created_at DESC"
        ).fetchall()
        callback_rows = db.execute(
            "SELECT callback_id,client_id,uri FROM callbacks ORDER BY callback_id"
        ).fetchall()
    callbacks_by_client: dict[str, list[sqlite3.Row]] = {}
    for callback in callback_rows:
        callbacks_by_client.setdefault(callback["client_id"], []).append(callback)

    csrf = html.escape(csrf_token(request), quote=True)
    message = f"<p class='notice'>{html.escape(notice)}</p>" if notice else ""
    if one_time_secret:
        client_id, secret = one_time_secret
        message += (
            "<section class='notice'><h2>Credencial mostrada una sola vez</h2>"
            "<p>Copia el secreto y guárdalo en el backend cliente. Después no se puede volver a consultar.</p>"
            f"<p>Client ID: <code>{html.escape(client_id)}</code></p>"
            f"<p>Client secret: <code>{html.escape(secret)}</code></p></section>"
        )

    content = (
        "<h1>Administración de clientes</h1>"
        "<p>Los secretos existentes solo se conservan como hashes; crear o rotar muestra el nuevo valor una vez.</p>"
        f"{message}<form method='post' action='/admin/logout' class='inline'>"
        f"<input type='hidden' name='csrf_token' value='{csrf}'><button>Cerrar sesión</button></form>"
        "<h2>Registrar cliente</h2><form method='post' action='/admin/clients'>"
        f"<input type='hidden' name='csrf_token' value='{csrf}'>"
        "<label>Nombre descriptivo<br><input name='name' maxlength='80' required></label><br>"
        "<label>Callbacks permitidas (una URI por línea, opcional)<br>"
        "<textarea name='callbacks' placeholder='https://cliente.ejemplo.com/oauth/minecraft/callback'></textarea></label><br>"
        "<button type='submit'>Crear cliente y generar secreto</button></form>"
        "<h2>Clientes registrados</h2>"
    )
    if not clients:
        content += "<p>Aún no hay clientes registrados.</p>"
    for client in clients:
        client_id = html.escape(client["client_id"])
        active = client["revoked_at"] is None
        status = "Activo" if active else f"Revocado ({html.escape(client['revoked_at'])})"
        content += (
            "<section><hr>"
            f"<h3>{html.escape(client['name'])} <small>— {status}</small></h3>"
            f"<p>Client ID: <code>{client_id}</code><br>Creado: {html.escape(client['created_at'])}</p>"
        )
        if active:
            content += (
                f"<form method='post' action='/admin/clients/{client_id}/rotate-secret' class='inline'>"
                f"<input type='hidden' name='csrf_token' value='{csrf}'><button>Rotar secreto</button></form>"
                f"<form method='post' action='/admin/clients/{client_id}/revoke' class='inline'>"
                f"<input type='hidden' name='csrf_token' value='{csrf}'><button>Revocar cliente</button></form>"
                f"<form method='post' action='/admin/clients/{client_id}/callbacks'>"
                f"<input type='hidden' name='csrf_token' value='{csrf}'>"
                "<label>Añadir callback HTTPS<br><input type='url' name='uri' placeholder='https://cliente.ejemplo.com/callback' required></label> "
                "<button>Añadir</button></form>"
            )
        existing = callbacks_by_client.get(client["client_id"], [])
        content += "<h4>Callbacks registradas</h4>"
        if existing:
            content += "<ul>"
            for callback in existing:
                uri = html.escape(callback["uri"])
                callback_id = callback["callback_id"]
                content += (
                    f"<li><code>{uri}</code> "
                    + (f"<form method='post' action='/admin/callbacks/{callback_id}/delete' class='inline'>"
                       f"<input type='hidden' name='csrf_token' value='{csrf}'><button>Quitar</button></form>" if active else "")
                    + "</li>"
                )
            content += "</ul>"
        else:
            content += "<p>Sin callbacks registradas.</p>"
        content += "</section>"

    return secure_page(form_html("Administración de clientes", content))


def request_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def login_is_limited(ip: str) -> bool:
    now = time.monotonic()
    with _login_lock:
        first, attempts = _login_failures.get(ip, (now, 0))
        if now - first > 900:
            _login_failures.pop(ip, None)
            return False
        return attempts >= 5


def record_failed_login(ip: str) -> None:
    now = time.monotonic()
    with _login_lock:
        first, attempts = _login_failures.get(ip, (now, 0))
        if now - first > 900:
            first, attempts = now, 0
        _login_failures[ip] = (first, attempts + 1)


def clear_login_failures(ip: str) -> None:
    with _login_lock:
        _login_failures.pop(ip, None)


@router.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request) -> Response:
    if is_admin(request):
        return dashboard(request, request.query_params.get("notice", ""))
    if request.session.get("admin_mfa_pending"):
        return RedirectResponse("/admin/mfa", status_code=303)
    if request.session.get("admin_setup_pending"):
        return RedirectResponse("/admin/setup-mfa", status_code=303)
    return login_page(request)


@router.get("/admin/login")
def admin_login_page_alias() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/login")
async def admin_login(request: Request) -> Response:
    form = await read_form(request)
    if not csrf_valid(request, form):
        return login_page(request, "Solicitud no válida. Recarga la página e inténtalo de nuevo.", 403)
    ip = request_ip(request)
    if login_is_limited(ip):
        return login_page(request, "Demasiados intentos. Espera 15 minutos.", 429)

    username_ok = hmac.compare_digest(form.get("username", "").encode(), ADMIN_USERNAME.encode())
    password_ok = hmac.compare_digest(form.get("password", "").encode(), ADMIN_PASSWORD.encode())
    if not (username_ok and password_ok):
        record_failed_login(ip)
        return login_page(request, "Usuario o contraseña incorrectos.", 401)

    clear_login_failures(ip)
    request.session.clear()
    request.session["admin_csrf"] = secrets.token_urlsafe(32)
    if totp_status():
        request.session["admin_mfa_pending"] = True
        return RedirectResponse("/admin/mfa", status_code=303)
    request.session["admin_setup_pending"] = True
    return RedirectResponse("/admin/setup-mfa", status_code=303)


@router.get("/admin/mfa")
def admin_mfa(request: Request) -> Response:
    if is_admin(request):
        return admin_redirect()
    if not request.session.get("admin_mfa_pending"):
        return admin_redirect()
    return admin_mfa_page(request)


@router.post("/admin/mfa")
async def verify_admin_mfa(request: Request) -> Response:
    form = await read_form(request)
    if not request.session.get("admin_mfa_pending"):
        return admin_redirect()
    if not csrf_valid(request, form):
        return admin_mfa_page(request, "Solicitud no válida. Recarga la página.", 403)
    ip = request_ip(request)
    if login_is_limited(ip):
        return admin_mfa_page(request, "Demasiados intentos. Espera 15 minutos.", 429)
    try:
        valid = verify_totp(form.get("code", "").strip())
    except RuntimeError as exc:
        return admin_mfa_page(request, str(exc), 500)
    if not valid:
        record_failed_login(ip)
        return admin_mfa_page(request, "Código incorrecto o caducado.", 401)
    clear_login_failures(ip)
    establish_admin_session(request)
    return admin_redirect()


@router.get("/admin/setup-mfa")
def setup_admin_mfa(request: Request) -> Response:
    if is_admin(request):
        return admin_redirect()
    if not request.session.get("admin_setup_pending") or totp_status():
        return admin_redirect()
    return totp_setup_page(request)


@router.post("/admin/setup-mfa")
async def confirm_admin_mfa_setup(request: Request) -> Response:
    form = await read_form(request)
    if not request.session.get("admin_setup_pending") or totp_status():
        return admin_redirect()
    if not csrf_valid(request, form):
        return totp_setup_page(request, "Solicitud no válida. Recarga la página.", 403)
    ip = request_ip(request)
    if login_is_limited(ip):
        return totp_setup_page(request, "Demasiados intentos. Espera 15 minutos.", 429)
    try:
        valid = verify_totp(form.get("code", "").strip())
    except RuntimeError as exc:
        return totp_setup_page(request, str(exc), 500)
    if not valid:
        record_failed_login(ip)
        return totp_setup_page(request, "Código incorrecto o caducado; vuelve a probar el código actual.", 401)

    with database() as db:
        db.execute("UPDATE admin_totp SET enabled=1 WHERE singleton=1")
    clear_login_failures(ip)
    establish_admin_session(request)
    return admin_redirect()


@router.post("/admin/logout")
async def admin_logout(request: Request) -> Response:
    form = await read_form(request)
    if not is_admin(request) or not csrf_valid(request, form):
        return secure_page(form_html("Solicitud no válida", "<p>La sesión ha caducado. Vuelve a iniciar sesión.</p>"), 403)
    request.session.clear()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/clients")
async def create_client(request: Request) -> Response:
    form = await read_form(request)
    if not is_admin(request):
        return admin_redirect()
    if not csrf_valid(request, form):
        return dashboard(request, "Solicitud CSRF inválida.")
    name = form.get("name", "").strip()
    if not name or len(name) > 80:
        return dashboard(request, "El nombre debe tener entre 1 y 80 caracteres.")
    callbacks = [line.strip() for line in form.get("callbacks", "").splitlines() if line.strip()]
    if len(callbacks) > 20:
        return dashboard(request, "Puedes registrar como máximo 20 callbacks al crear un cliente.")
    try:
        callbacks = [validate_callback_uri(uri) for uri in callbacks]
    except ValueError as exc:
        return dashboard(request, str(exc))

    client_id = "cl_" + secrets.token_urlsafe(18)
    client_secret = secrets.token_urlsafe(40)
    salt, digest = hash_client_secret(client_secret)
    try:
        with database() as db:
            db.execute(
                "INSERT INTO clients(client_id,name,secret_salt,secret_hash,created_at) VALUES(?,?,?,?,?)",
                (client_id, name, salt, digest, now_iso()),
            )
            for uri in callbacks:
                db.execute(
                    "INSERT INTO callbacks(client_id,uri,created_at) VALUES(?,?,?)",
                    (client_id, uri, now_iso()),
                )
    except sqlite3.IntegrityError:
        return dashboard(request, "El cliente o una callback ya existe.")
    return dashboard(request, "Cliente creado.", (client_id, client_secret))


@router.post("/admin/clients/{client_id}/callbacks")
async def add_callback(request: Request, client_id: str) -> Response:
    form = await read_form(request)
    if not is_admin(request):
        return admin_redirect()
    if not csrf_valid(request, form):
        return dashboard(request, "Solicitud CSRF inválida.")
    try:
        uri = validate_callback_uri(form.get("uri", ""))
        with database() as db:
            client = db.execute(
                "SELECT revoked_at FROM clients WHERE client_id=?", (client_id,)
            ).fetchone()
            if not client or client["revoked_at"]:
                return dashboard(request, "Cliente inexistente o revocado.")
            count = db.execute(
                "SELECT COUNT(*) AS n FROM callbacks WHERE client_id=?", (client_id,)
            ).fetchone()["n"]
            if count >= 20:
                return dashboard(request, "Un cliente puede tener como máximo 20 callbacks.")
            db.execute(
                "INSERT INTO callbacks(client_id,uri,created_at) VALUES(?,?,?)",
                (client_id, uri, now_iso()),
            )
    except ValueError as exc:
        return dashboard(request, str(exc))
    except sqlite3.IntegrityError:
        return dashboard(request, "Esa callback ya está registrada para este cliente.")
    return admin_redirect_with_notice("Callback añadida.")


def admin_redirect_with_notice(notice: str) -> RedirectResponse:
    from urllib.parse import quote

    return RedirectResponse("/admin?notice=" + quote(notice), status_code=303)


@router.post("/admin/callbacks/{callback_id}/delete")
async def delete_callback(request: Request, callback_id: int) -> Response:
    form = await read_form(request)
    if not is_admin(request):
        return admin_redirect()
    if not csrf_valid(request, form):
        return dashboard(request, "Solicitud CSRF inválida.")
    with database() as db:
        db.execute("DELETE FROM callbacks WHERE callback_id=?", (callback_id,))
    return admin_redirect_with_notice("Callback eliminada.")


@router.post("/admin/clients/{client_id}/rotate-secret")
async def rotate_secret(request: Request, client_id: str) -> Response:
    form = await read_form(request)
    if not is_admin(request):
        return admin_redirect()
    if not csrf_valid(request, form):
        return dashboard(request, "Solicitud CSRF inválida.")
    new_secret = secrets.token_urlsafe(40)
    salt, digest = hash_client_secret(new_secret)
    with database() as db:
        result = db.execute(
            "UPDATE clients SET secret_salt=?,secret_hash=? WHERE client_id=? AND revoked_at IS NULL",
            (salt, digest, client_id),
        )
        if result.rowcount != 1:
            return dashboard(request, "Cliente inexistente o revocado.")
        db.execute("DELETE FROM client_tokens WHERE client_id=?", (client_id,))
        db.execute("DELETE FROM authorization_codes WHERE client_id=?", (client_id,))
    return dashboard(request, "Secreto rotado. El secreto anterior deja de servir.", (client_id, new_secret))


@router.post("/admin/clients/{client_id}/revoke")
async def revoke_client(request: Request, client_id: str) -> Response:
    form = await read_form(request)
    if not is_admin(request):
        return admin_redirect()
    if not csrf_valid(request, form):
        return dashboard(request, "Solicitud CSRF inválida.")
    with database() as db:
        result = db.execute(
            "UPDATE clients SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL",
            (now_iso(), client_id),
        )
        if result.rowcount != 1:
            return dashboard(request, "Cliente inexistente o ya revocado.")
        db.execute("DELETE FROM client_tokens WHERE client_id=?", (client_id,))
        db.execute("DELETE FROM authorization_codes WHERE client_id=?", (client_id,))
    return admin_redirect_with_notice("Cliente revocado.")

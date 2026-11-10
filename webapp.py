"""API web que obtiene el perfil Java del usuario que inicia sesión."""

from __future__ import annotations

import os
import hashlib
import hmac
import ipaddress
import re
import secrets
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import msal
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

from admin_panel import database, router as admin_router, verify_client_secret

CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
REDIRECT_URI = f"{PUBLIC_BASE_URL}/auth/callback"
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
COOKIE_SAME_SITE = os.getenv("COOKIE_SAME_SITE", "lax").lower()
CORS_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
AUTHORITY = "https://login.microsoftonline.com/consumers"
SCOPES = ["XboxLive.signin"]
XBOX_USER_AUTH = "https://user.auth.xboxlive.com/user/authenticate"
XBOX_XSTS_AUTH = "https://xsts.auth.xboxlive.com/xsts/authorize"
MINECRAFT = "https://api.minecraftservices.com"
HTTP_TIMEOUT = 25
AUTH_MODE = os.getenv("AUTH_MODE", "development").strip().lower()
MOCK_PROFILE_NAME = os.getenv("MOCK_PROFILE_NAME", "PruebaMinecraft").strip()
MOCK_PROFILE_UUID = os.getenv(
    "MOCK_PROFILE_UUID", "12345678-1234-4234-8234-123456789abc"
).strip()

if AUTH_MODE not in {"microsoft", "development"}:
    raise RuntimeError("AUTH_MODE debe ser microsoft o development.")
if AUTH_MODE == "development":
    public_host = urlsplit(PUBLIC_BASE_URL).hostname
    if public_host not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("AUTH_MODE=development solo se permite con PUBLIC_BASE_URL local.")
if AUTH_MODE == "microsoft" and (not CLIENT_ID or not CLIENT_SECRET):
    raise RuntimeError("Configura MICROSOFT_CLIENT_ID y MICROSOFT_CLIENT_SECRET en .env.")
if not SESSION_SECRET:
    raise RuntimeError("Configura SESSION_SECRET en .env.")
if AUTH_MODE == "development":
    if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", MOCK_PROFILE_NAME):
        raise RuntimeError("MOCK_PROFILE_NAME debe tener entre 3 y 16 letras, números o guiones bajos.")
    try:
        MOCK_PROFILE_UUID = str(uuid.UUID(MOCK_PROFILE_UUID))
    except ValueError as exc:
        raise RuntimeError("MOCK_PROFILE_UUID debe ser un UUID válido.") from exc
if COOKIE_SAME_SITE not in {"lax", "strict", "none"}:
    raise RuntimeError("COOKIE_SAME_SITE debe ser lax, strict o none.")
if COOKIE_SAME_SITE == "none" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SECURE=true es obligatorio con COOKIE_SAME_SITE=none.")
if not PUBLIC_BASE_URL.startswith(("http://", "https://")):
    raise RuntimeError("PUBLIC_BASE_URL debe comenzar por http:// o https://.")


class LoginError(Exception):
    """Error de autenticación o acceso a los servicios Xbox/Minecraft."""


def post_json(url: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        response = requests.post(url, json=body, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        raise LoginError("No se pudo conectar con los servicios Xbox/Minecraft.") from exc

    if not response.ok:
        if response.status_code == 403 and url.endswith("/authentication/login_with_xbox"):
            raise LoginError(
                "Minecraft rechazó el registro de la aplicación (403). El Client ID de Entra "
                "puede necesitar autorización/registro de Minecraft. Consulta la guía oficial "
                "en README.md y solicita la aprobación antes de reintentar."
            )
        raise LoginError(f"El servicio Xbox/Minecraft respondió HTTP {response.status_code}.")

    try:
        return response.json()
    except ValueError as exc:
        raise LoginError("El servicio Xbox/Minecraft devolvió una respuesta JSON no válida.") from exc


def get_json(url: str, token: str) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise LoginError("No se pudo consultar el perfil de Minecraft.") from exc

    if response.status_code == 404:
        raise LoginError(
            "La cuenta Microsoft inició sesión, pero no tiene un perfil de Minecraft Java "
            "disponible. Puede no tener acceso/licencia a Java Edition, o el perfil todavía "
            "no se ha creado. Comprueba el acceso desde el Launcher oficial."
        )
    if response.status_code == 401:
        raise LoginError("Minecraft no aceptó el token de acceso; vuelve a iniciar sesión.")
    if not response.ok:
        raise LoginError(f"La consulta del perfil respondió HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError as exc:
        raise LoginError("Minecraft devolvió una respuesta de perfil no válida.") from exc


def get_minecraft_token(msa_token: str) -> str:
    xbl = post_json(
        XBOX_USER_AUTH,
        {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={msa_token}",
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        },
    )
    xbl_token = xbl.get("Token")
    if not xbl_token:
        raise LoginError("Xbox Live no devolvió un token de usuario.")

    xsts = post_json(
        XBOX_XSTS_AUTH,
        {
            "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT",
        },
    )
    xsts_token = xsts.get("Token")
    claims = xsts.get("DisplayClaims", {}).get("xui", [])
    user_hash = claims[0].get("uhs") if claims else None
    if not xsts_token or not user_hash:
        raise LoginError("Xbox Live no devolvió las credenciales XSTS requeridas.")

    minecraft = post_json(
        f"{MINECRAFT}/authentication/login_with_xbox",
        {"identityToken": f"XBL3.0 x={user_hash};{xsts_token}"},
    )
    token = minecraft.get("access_token")
    if not token:
        raise LoginError("Minecraft no devolvió un token de acceso.")
    return token


app = FastAPI(
    title="Minecraft Java Profile API",
    version="1.0.0",
    description="Obtiene el perfil Java de Minecraft del usuario autenticado.",
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="minecraft_profile_session",
    max_age=1800,
    same_site=COOKIE_SAME_SITE,
    https_only=COOKIE_SECURE,
)
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

app.include_router(admin_router)


@app.middleware("http")
async def restrict_development_mode_to_loopback(request: Request, call_next: Any) -> Response:
    if AUTH_MODE == "development":
        remote_host = request.client.host if request.client else ""
        try:
            is_loopback = ipaddress.ip_address(remote_host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            return api_error("development_mode_local_only", "El modo de desarrollo solo acepta conexiones locales.", 403)
    return await call_next(request)

# OAuth flow state is transient. Use a shared encrypted store before multiple workers.
pending_flows: dict[str, dict[str, Any]] = {}
basic_auth = HTTPBasic(auto_error=False)
bearer_auth = HTTPBearer(auto_error=False)
CLIENT_TOKEN_TTL = 600
AUTH_CODE_TTL = 90


class AuthorizationRequest(BaseModel):
    callback_uri: str = Field(min_length=1, max_length=2048)
    state: str = Field(min_length=16, max_length=512)


class CodeExchangeRequest(BaseModel):
    code: str = Field(min_length=20, max_length=256)
    state: str = Field(min_length=16, max_length=512)


def api_error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def authenticate_basic(credentials: HTTPBasicCredentials | None) -> str:
    if credentials is None:
        raise HTTPException(401, "invalid_client", headers={"WWW-Authenticate": "Basic"})
    client_id = credentials.username
    with database() as db:
        row = db.execute(
            "SELECT secret_salt,secret_hash,revoked_at FROM clients WHERE client_id=?",
            (client_id,),
        ).fetchone()
    if not row or row["revoked_at"] is not None:
        raise HTTPException(401, "invalid_client", headers={"WWW-Authenticate": "Basic"})
    if not verify_client_secret(credentials.password, row["secret_salt"], row["secret_hash"]):
        raise HTTPException(401, "invalid_client", headers={"WWW-Authenticate": "Basic"})
    return client_id


def authenticate_bearer(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "invalid_token", headers={"WWW-Authenticate": "Bearer"})
    token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
    with database() as db:
        row = db.execute(
            "SELECT t.client_id,t.expires_at,c.revoked_at FROM client_tokens t "
            "JOIN clients c ON c.client_id=t.client_id WHERE t.token_hash=?",
            (token_hash,),
        ).fetchone()
    if not row or row["revoked_at"] is not None or row["expires_at"] <= time.time():
        raise HTTPException(401, "invalid_token", headers={"WWW-Authenticate": "Bearer"})
    return row["client_id"]


def confidential_client() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )


def error_response(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
    )


def browser_base_url(request: Request) -> str:
    if AUTH_MODE != "development":
        return PUBLIC_BASE_URL
    host = request.url.hostname
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return PUBLIC_BASE_URL
    return f"{request.url.scheme}://{request.url.netloc}"


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    profile = request.session.get("profile")
    if profile:
        body = (
            "<h1>Perfil Minecraft Java</h1>"
            f"<p>Nombre: <strong>{profile['name']}</strong></p>"
            f"<p>UUID: <code>{profile['id']}</code></p>"
            '<p><a href="/api/me">Ver respuesta JSON</a></p>'
            '<form method="post" action="/auth/logout"><button>Cerrar sesión</button></form>'
        )
    else:
        login_label = (
            "Iniciar sesión de prueba (perfil simulado)"
            if AUTH_MODE == "development"
            else "Iniciar sesión con Microsoft"
        )
        body = (
            "<h1>Minecraft Java Profile API</h1>"
            f'<p><a href="/auth/login">{login_label}</a></p>'
            '<p>Tras autorizar, consulta <code>/api/me</code> para obtener tu perfil.</p>'
        )
    return HTMLResponse(
        "<!doctype html><html lang='es'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Minecraft Profile API</title><body>" + body + "</body></html>",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login")
def login_alias() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=303)


@app.post("/oauth/token")
async def issue_client_token(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(basic_auth),
) -> JSONResponse:
    client_id = authenticate_basic(credentials)
    form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
    if form.get("grant_type", [""])[0] != "client_credentials":
        return api_error("unsupported_grant_type", "Usa grant_type=client_credentials.", 400)

    access_token = secrets.token_urlsafe(40)
    expires_at = time.time() + CLIENT_TOKEN_TTL
    token_hash = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    with database() as db:
        db.execute("DELETE FROM client_tokens WHERE expires_at<=?", (time.time(),))
        db.execute(
            "INSERT INTO client_tokens(token_hash,client_id,expires_at) VALUES(?,?,?)",
            (token_hash, client_id, expires_at),
        )
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": CLIENT_TOKEN_TTL,
            "scope": "minecraft.profile.read",
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.post("/v1/authorizations")
def start_client_authorization(
    payload: AuthorizationRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth),
) -> JSONResponse:
    client_id = authenticate_bearer(credentials)
    with database() as db:
        callback = db.execute(
            "SELECT 1 FROM callbacks cb JOIN clients c ON c.client_id=cb.client_id "
            "WHERE cb.client_id=? AND cb.uri=? AND c.revoked_at IS NULL",
            (client_id, payload.callback_uri),
        ).fetchone()
    if not callback:
        return api_error(
            "invalid_callback",
            "La URI no está registrada para este cliente; usa una callback exacta del panel.",
            400,
        )

    if AUTH_MODE == "development":
        mock_state = secrets.token_urlsafe(32)
        flow = {
            "state": mock_state,
            "auth_uri": f"{PUBLIC_BASE_URL}/dev/authorize?state={mock_state}",
        }
    else:
        flow = confidential_client().initiate_auth_code_flow(
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )
        if "auth_uri" not in flow or "state" not in flow:
            return api_error("auth_flow_error", "No se pudo iniciar el flujo Microsoft.", 502)

    now = time.time()
    for old_state, pending in list(pending_flows.items()):
        if now - pending["created_at"] > 600:
            pending_flows.pop(old_state, None)
    pending_flows[flow["state"]] = {
        "created_at": now,
        "flow": flow,
        "mode": "client",
        "client_id": client_id,
        "callback_uri": payload.callback_uri,
        "client_state": payload.state,
    }
    return JSONResponse(
        content={
            "authorization_url": flow["auth_uri"],
            "expires_in": 600,
            "test_mode": AUTH_MODE == "development",
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.post("/v1/authorizations/exchange")
def exchange_authorization_code(
    payload: CodeExchangeRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth),
) -> JSONResponse:
    client_id = authenticate_bearer(credentials)
    code_hash = hashlib.sha256(payload.code.encode("utf-8")).hexdigest()
    now = time.time()
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT client_id,client_state,profile_name,profile_uuid,expires_at,consumed_at "
            "FROM authorization_codes WHERE code_hash=?",
            (code_hash,),
        ).fetchone()
        if (
            not row
            or row["client_id"] != client_id
            or row["consumed_at"] is not None
            or row["expires_at"] <= now
            or not hmac.compare_digest(row["client_state"].encode(), payload.state.encode())
        ):
            return api_error("invalid_or_expired_code", "Código inválido, caducado o ya utilizado.", 400)
        updated = db.execute(
            "UPDATE authorization_codes SET consumed_at=? "
            "WHERE code_hash=? AND consumed_at IS NULL AND expires_at>?",
            (now, code_hash, now),
        )
        if updated.rowcount != 1:
            return api_error("invalid_or_expired_code", "Código inválido, caducado o ya utilizado.", 400)
        result = {"edition": "java", "name": row["profile_name"], "uuid": row["profile_uuid"]}
    return JSONResponse(
        content=result,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/auth/login")
def auth_login(request: Request) -> Response:
    local_base_url = browser_base_url(request)
    if AUTH_MODE == "development":
        state = secrets.token_urlsafe(32)
        flow = {"state": state, "auth_uri": f"{local_base_url}/dev/authorize?state={state}"}
    else:
        flow = confidential_client().initiate_auth_code_flow(
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )
        if "auth_uri" not in flow or "state" not in flow:
            return error_response(
                "auth_flow_error",
                str(flow.get("error_description") or flow.get("error") or "No se pudo iniciar OAuth."),
                502,
            )

    now = time.time()
    for old_state, pending in list(pending_flows.items()):
        if now - pending["created_at"] > 600:
            pending_flows.pop(old_state, None)
    pending_flows[flow["state"]] = {
        "created_at": now,
        "flow": flow,
        "mode": "browser",
        "browser_base_url": local_base_url,
    }
    request.session.clear()
    request.session["oauth_state"] = flow["state"]
    return RedirectResponse(flow["auth_uri"], status_code=302)


@app.get("/auth/callback")
def auth_callback(request: Request) -> Response:
    state = request.query_params.get("state")
    if not state:
        return error_response("invalid_state", "Falta el estado OAuth; vuelve a iniciar sesión.", 400)
    pending = pending_flows.pop(state, None)
    if pending is None or time.time() - pending["created_at"] > 600:
        return error_response("expired_login", "El inicio de sesión caducó; vuelve a intentarlo.", 400)
    mode = pending["mode"]
    if mode == "browser":
        session_state = request.session.pop("oauth_state", None)
        if not hmac.compare_digest(str(session_state or "").encode(), state.encode()):
            return error_response("invalid_state", "Estado OAuth inválido; vuelve a iniciar sesión.", 400)
    flow = pending["flow"]

    def client_callback_error(error_code: str, status: int, message: str) -> Response:
        if mode != "client":
            return error_response(error_code, message, status)
        return finish_client_callback(
            pending,
            {"error": error_code, "state": pending["client_state"]},
        )

    if request.query_params.get("error"):
        return client_callback_error(
            "microsoft_login_failed", 401, "El usuario canceló o no completó el inicio de sesión Microsoft."
        )

    try:
        result = confidential_client().acquire_token_by_auth_code_flow(
            flow,
            dict(request.query_params),
        )
    except ValueError as exc:
        return client_callback_error("microsoft_token_error", 401, str(exc))

    msa_token = result.get("access_token")
    if not msa_token:
        message = result.get("error_description") or result.get("error") or "Microsoft no emitió un token."
        return client_callback_error("microsoft_token_error", 401, message)

    try:
        minecraft_token = get_minecraft_token(msa_token)
        profile = get_json(f"{MINECRAFT}/minecraft/profile", minecraft_token)
    except LoginError as exc:
        message = str(exc)
        if "no tiene un perfil de Minecraft Java" in message:
            return client_callback_error("no_minecraft_profile", 404, message)
        if "rechazó el registro de la aplicación" in message:
            return client_callback_error("minecraft_app_not_authorized", 502, message)
        return client_callback_error("minecraft_service_error", 502, message)

    return finalize_profile(request, pending, profile)


def finalize_profile(request: Request, pending: dict[str, Any], profile: dict[str, Any]) -> Response:
    name, profile_id = profile.get("name"), profile.get("id")
    if not name or not profile_id:
        if pending["mode"] == "client":
            return finish_client_callback(
                pending,
                {"error": "invalid_profile", "state": pending["client_state"]},
            )
        return error_response("invalid_profile", "Minecraft no devolvió nombre y UUID.", 502)
    try:
        profile_id = str(uuid.UUID(profile_id))
    except (ValueError, AttributeError):
        pass

    if pending["mode"] == "client":
        code = secrets.token_urlsafe(32)
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        expires_at = time.time() + AUTH_CODE_TTL
        with database() as db:
            db.execute("DELETE FROM authorization_codes WHERE expires_at<=? OR consumed_at IS NOT NULL", (time.time(),))
            db.execute(
                "INSERT INTO authorization_codes(code_hash,client_id,callback_uri,client_state,"
                "profile_name,profile_uuid,expires_at) VALUES(?,?,?,?,?,?,?)",
                (
                    code_hash,
                    pending["client_id"],
                    pending["callback_uri"],
                    pending["client_state"],
                    name,
                    profile_id,
                    expires_at,
                ),
            )
        return finish_client_callback(
            pending,
            {"code": code, "state": pending["client_state"]},
        )

    # Solo se conserva el perfil público en la cookie; nunca los bearer tokens.
    request.session.clear()
    request.session["profile"] = {"name": name, "id": profile_id}
    return RedirectResponse(
        f"{pending.get('browser_base_url', PUBLIC_BASE_URL)}/",
        status_code=303,
    )


def finish_client_callback(pending: dict[str, Any], parameters: dict[str, str]) -> Response:
    client_id = pending["client_id"]
    callback_uri = pending["callback_uri"]
    with database() as db:
        active = db.execute(
            "SELECT 1 FROM clients c JOIN callbacks cb ON cb.client_id=c.client_id "
            "WHERE c.client_id=? AND c.revoked_at IS NULL AND cb.uri=?",
            (client_id, callback_uri),
        ).fetchone()
    if not active:
        return error_response(
            "callback_revoked", "El cliente o la callback se revocó durante el inicio de sesión.", 400
        )
    return RedirectResponse(
        f"{callback_uri}?{urlencode(parameters)}",
        status_code=303,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
        },
    )


@app.get("/dev/authorize")
def mock_authorize(request: Request, state: str) -> Response:
    if AUTH_MODE != "development":
        return error_response("not_found", "Ruta no disponible.", 404)
    pending = pending_flows.get(state)
    if pending is None or time.time() - pending["created_at"] > 600:
        pending_flows.pop(state, None)
        return error_response("expired_test_flow", "La prueba caducó; inicia el flujo de nuevo.", 400)
    if pending["mode"] == "browser":
        session_state = request.session.get("oauth_state", "")
        if not hmac.compare_digest(str(session_state).encode(), state.encode()):
            return error_response("invalid_state", "Estado de prueba inválido.", 400)
        request.session.pop("oauth_state", None)

    pending_flows.pop(state, None)
    response = finalize_profile(
        request,
        pending,
        {"name": MOCK_PROFILE_NAME, "id": MOCK_PROFILE_UUID},
    )
    response.headers["X-Auth-Mode"] = "development"
    return response


@app.get("/api/me")
def get_my_profile(request: Request) -> JSONResponse:
    profile = request.session.get("profile")
    if not profile:
        return error_response("not_authenticated", "Inicia sesión en /auth/login primero.", 401)
    return JSONResponse(
        content={"edition": "java", "name": profile["name"], "uuid": profile["id"]},
        headers={"Cache-Control": "no-store"},
    )


@app.post("/auth/logout")
def logout(request: Request) -> JSONResponse:
    request.session.clear()
    return JSONResponse({"status": "signed_out"}, headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("webapp:app", host="127.0.0.1", port=8000, reload=False)

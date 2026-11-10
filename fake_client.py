"""Cliente backend local de demostración para la Minecraft Profile API."""

from __future__ import annotations

import html
import hmac
import os
import secrets

import requests
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware


load_dotenv()

API_BASE_URL = os.getenv("DEMO_API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CLIENT_ID = os.getenv("DEMO_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("DEMO_CLIENT_SECRET", "")
SESSION_SECRET = os.getenv("DEMO_SESSION_SECRET", "")
CALLBACK_URL = os.getenv(
    "DEMO_CALLBACK_URL", "http://127.0.0.1:8001/callback"
).strip()

if not CLIENT_ID or not CLIENT_SECRET:
    raise RuntimeError("Configura DEMO_CLIENT_ID y DEMO_CLIENT_SECRET en .env.")
if len(SESSION_SECRET) < 32 or SESSION_SECRET.lower().startswith("replace-"):
    raise RuntimeError("Configura DEMO_SESSION_SECRET con una clave aleatoria de 32 caracteres o más.")

app = FastAPI(title="Fake Minecraft API Client", docs_url=None, redoc_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="demo_client_session",
    max_age=600,
    same_site="lax",
    https_only=False,
)


def page(content: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html lang='es'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Cliente de prueba Minecraft</title>"
        "<body style='font:16px system-ui;max-width:700px;margin:3rem auto;padding:0 1rem'>"
        + content
        + "</body></html>",
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


def request_api_token() -> str:
    response = requests.post(
        f"{API_BASE_URL}/oauth/token",
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        timeout=15,
    )
    if not response.ok:
        raise RuntimeError(f"No se pudo autenticar el cliente ({response.status_code}): {response.text[:400]}")
    token = response.json().get("access_token")
    if not token:
        raise RuntimeError("La API no devolvió un token de cliente.")
    return token


@app.get("/")
def home(request: Request) -> HTMLResponse:
    profile = request.session.get("profile")
    if profile:
        content = (
            "<h1>Cliente backend de demostración</h1>"
            "<p>Perfil recibido desde la API:</p>"
            f"<p>Nombre: <strong>{html.escape(profile['name'])}</strong></p>"
            f"<p>UUID: <code>{html.escape(profile['uuid'])}</code></p>"
            '<p><a href="/logout">Cerrar sesión local</a></p>'
        )
    else:
        content = (
            "<h1>Cliente backend de demostración</h1>"
            "<p>Este servicio usa credenciales privadas en su servidor y una callback registrada.</p>"
            '<p><a href="/login">Conectar con Minecraft</a></p>'
        )
    return page(content)


@app.get("/login")
def start_login(request: Request) -> Response:
    state = secrets.token_urlsafe(32)
    request.session.clear()
    request.session["oauth_state"] = state
    try:
        client_token = request_api_token()
        response = requests.post(
            f"{API_BASE_URL}/v1/authorizations",
            headers={"Authorization": f"Bearer {client_token}"},
            json={"callback_uri": CALLBACK_URL, "state": state},
            timeout=15,
        )
        if not response.ok:
            raise RuntimeError(f"No se pudo iniciar la autorización ({response.status_code}): {response.text[:400]}")
        authorization_url = response.json().get("authorization_url")
        if not authorization_url:
            raise RuntimeError("La API no devolvió authorization_url.")
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        request.session.clear()
        return page(f"<h1>Error al iniciar sesión</h1><p>{html.escape(str(exc))}</p><p><a href='/'>Volver</a></p>", 502)
    return RedirectResponse(authorization_url, status_code=303)


@app.get("/callback")
def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    expected_state = request.session.pop("oauth_state", "")
    if not state or not hmac.compare_digest(str(expected_state).encode(), state.encode()):
        request.session.clear()
        return page("<h1>Estado inválido</h1><p>Vuelve a iniciar la autorización desde el cliente.</p>", 400)
    if error:
        request.session.clear()
        return page(f"<h1>Autorización no completada</h1><p>{html.escape(error)}</p><p><a href='/'>Volver</a></p>", 400)
    if not code:
        request.session.clear()
        return page("<h1>Falta el código de autorización</h1><p>Vuelve a intentarlo.</p>", 400)

    try:
        client_token = request_api_token()
        response = requests.post(
            f"{API_BASE_URL}/v1/authorizations/exchange",
            headers={"Authorization": f"Bearer {client_token}"},
            json={"code": code, "state": state},
            timeout=15,
        )
        if not response.ok:
            raise RuntimeError(f"No se pudo canjear el código ({response.status_code}): {response.text[:400]}")
        profile = response.json()
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        request.session.clear()
        return page(f"<h1>Error al recibir el perfil</h1><p>{html.escape(str(exc))}</p><p><a href='/'>Volver</a></p>", 502)

    if profile.get("edition") != "java" or not profile.get("name") or not profile.get("uuid"):
        request.session.clear()
        return page("<h1>Respuesta de perfil no válida</h1><p>La API no devolvió los campos esperados.</p>", 502)
    request.session.clear()
    request.session["profile"] = {
        "name": str(profile["name"]),
        "uuid": str(profile["uuid"]),
    }
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/", status_code=303)


if __name__ == "__main__":
    uvicorn.run("fake_client:app", host="127.0.0.1", port=8001, reload=False)

"""Obtiene el perfil propio de Minecraft Java con inicio de sesión Microsoft."""

from __future__ import annotations

import os
import sys
import uuid
from typing import Any

import msal
import requests
from dotenv import load_dotenv


AUTHORITY = "https://login.microsoftonline.com/consumers"
XBOX_USER_AUTH = "https://user.auth.xboxlive.com/user/authenticate"
XBOX_XSTS_AUTH = "https://xsts.auth.xboxlive.com/xsts/authorize"
MINECRAFT = "https://api.minecraftservices.com"
TIMEOUT = 25


class LoginError(Exception):
    """Error de autenticación o acceso a los servicios Minecraft."""


def post_json(url: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        response = requests.post(url, json=body, timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise LoginError(f"No se pudo conectar con el servicio ({url}): {exc}") from exc

    if not response.ok:
        try:
            details = response.json()
        except ValueError:
            details = response.text[:500]
        if response.status_code == 403 and url.endswith("/authentication/login_with_xbox"):
            raise LoginError(
                "Minecraft rechazó el registro de la aplicación (403). El Client ID de Entra "
                "puede necesitar autorización/registro de Minecraft. Consulta la guía oficial "
                "en README.md y solicita la aprobación antes de reintentar."
            )
        raise LoginError(
            f"El servicio respondió HTTP {response.status_code}: {details}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise LoginError("El servicio devolvió una respuesta JSON no válida.") from exc


def get_json(url: str, token: str) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise LoginError(f"No se pudo consultar el perfil de Minecraft: {exc}") from exc

    if response.status_code == 404:
        raise LoginError(
            "La cuenta Microsoft inició sesión, pero no tiene un perfil de Minecraft Java "
            "disponible. Puede no tener acceso/licencia a Java Edition, o el perfil todavía "
            "no se ha creado. Comprueba el acceso desde el Launcher oficial."
        )
    if response.status_code == 401:
        raise LoginError("Minecraft no aceptó el token de acceso; vuelve a iniciar sesión.")
    if not response.ok:
        raise LoginError(f"La consulta del perfil respondió HTTP {response.status_code}: "
                         f"{response.text[:500]}")
    try:
        return response.json()
    except ValueError as exc:
        raise LoginError("Minecraft devolvió una respuesta de perfil no válida.") from exc


def get_microsoft_token(client_id: str) -> str:
    app = msal.PublicClientApplication(client_id=client_id, authority=AUTHORITY)
    result = app.acquire_token_interactive(
        scopes=["XboxLive.signin"],
        prompt="select_account",
        port=0,
        timeout=300,
    )
    token = result.get("access_token")
    if not token:
        description = result.get("error_description") or result.get("error") or "sin detalles"
        if "AADSTS70002" in description or "client_secret" in description.lower():
            raise LoginError(
                "Entra está tratando este registro como una aplicación confidencial y exige "
                "un client_secret. Esta app de escritorio debe ser cliente público: en Entra "
                "abre Authentication > Add a platform > Mobile and desktop applications y "
                "agrega http://localhost; luego en Advanced settings activa Allow public "
                "client flows = Yes y guarda. Comprueba también que MICROSOFT_CLIENT_ID sea "
                "el Application (client) ID de ese mismo registro. No crees ni pongas un secreto."
            )
        raise LoginError(f"Microsoft no completó el inicio de sesión: {description}")
    return token


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


def main() -> int:
    load_dotenv()
    client_id = os.getenv("MICROSOFT_CLIENT_ID", "").strip()
    if not client_id:
        print("Falta MICROSOFT_CLIENT_ID. Copia .env.example a .env y añade el "
              "Application (client) ID del registro de Entra.", file=sys.stderr)
        return 2

    try:
        msa_token = get_microsoft_token(client_id)
        minecraft_token = get_minecraft_token(msa_token)
        profile = get_json(f"{MINECRAFT}/minecraft/profile", minecraft_token)
    except LoginError as exc:
        print(f"No se pudo obtener el perfil: {exc}", file=sys.stderr)
        return 1

    name = profile.get("name")
    profile_id = profile.get("id")
    if not name or not profile_id:
        print("Minecraft respondió, pero no incluyó nombre y UUID de perfil.", file=sys.stderr)
        return 1

    try:
        normalized_uuid = str(uuid.UUID(profile_id))
    except (ValueError, AttributeError):
        normalized_uuid = profile_id
    print("Perfil de Minecraft Java:")
    print(f"  Nombre: {name}")
    print(f"  UUID:   {normalized_uuid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

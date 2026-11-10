# Minecraft Java Profile API

Servicio web Python con FastAPI. El usuario inicia sesión con su propia cuenta Microsoft y la API devuelve el nombre y UUID de su perfil Java. No admite consultas por correo ni búsquedas de perfiles privados de otras personas.

## Endpoints

- `GET /auth/login`: inicia el flujo Authorization Code de Microsoft.
- `GET /auth/callback`: callback registrado en Entra; canjea el código y consulta Xbox/XSTS/Minecraft.
- `GET /api/me`: devuelve el perfil de la sesión actual como JSON.
- `POST /auth/logout`: cierra la sesión.
- `POST /oauth/token`: intercambia las credenciales de un cliente privado por un token Bearer de 10 minutos.
- `POST /v1/authorizations`: inicia una autorización de usuario, solo para un callback registrado para ese cliente.
- `POST /v1/authorizations/exchange`: canjea el código final de un solo uso por nombre y UUID.
- `/admin`: panel para registrar/revocar clientes y administrar sus callbacks.
- `GET /docs`: documentación interactiva de la API.

Ejemplo de respuesta de `GET /api/me`:

```json
{"edition":"java","name":"NombreJugador","uuid":"00000000-0000-0000-0000-000000000000"}
```

`/api/me` es el endpoint para la sesión directa del navegador. Los clientes backend privados usan el flujo de autorización de cliente descrito más abajo; no necesitan compartir una cookie de usuario.

## Requisito de Minecraft

Minecraft Services puede rechazar el Client ID con `403 Invalid app registration` si la aplicación no está registrada/autorizada por Minecraft. Sigue el [proceso oficial de Minecraft](https://help.minecraft.net/hc/en-us/articles/16254801392141). La configuración de Entra no elimina ese requisito. La API devuelve el error `minecraft_app_not_authorized` si recibe ese 403.

## Configuración de Microsoft Entra

Esta versión es un **cliente web confidencial del lado servidor**, distinto de la versión de consola:

1. En Entra, abre **App registrations** y selecciona el registro existente.
2. En **Authentication > Add a platform > Web**, agrega la URI exacta `http://localhost:8000/auth/callback` para desarrollo local. En producción agrega la URI HTTPS exacta del servidor, por ejemplo `https://api.ejemplo.com/auth/callback`.
3. En **Supported account types**, habilita cuentas Microsoft personales. La aplicación usa el tenant `consumers`.
4. No agregues una API de Xbox desde **API permissions**: el registro puede no mostrar ninguna y no hace falta configurar ahí un permiso de Xbox. Durante el inicio de sesión, la aplicación solicita el ámbito OAuth delegado `XboxLive.signin` (en el parámetro `scope`); no agregues permisos de Microsoft Graph para obtener el perfil de Minecraft. El acceso a Xbox y Minecraft se completa después mediante el intercambio de tokens que hace el backend.
5. En **Certificates & secrets**, crea un **Client secret**. Copia su campo **Value** inmediatamente a `MICROSOFT_CLIENT_SECRET` en el entorno del servidor. No lo pongas en el frontend, repositorio, ni publiques el `.env`. Un certificado también puede sustituir al secreto en producción; este ejemplo usa secreto.
6. Solicita el registro/autorización del Client ID para Minecraft Services mediante el proceso oficial indicado arriba.

Microsoft documenta el Authorization Code de MSAL Python y la diferencia entre clientes públicos y confidenciales en [MSAL Python: adquirir tokens](https://learn.microsoft.com/en-us/entra/msal/python/getting-started/acquiring-tokens). La URI de redirección debe coincidir con la registrada: [guía de redirect URI](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri).

## Panel de administración de clientes

Antes de arrancar, añade en `.env` credenciales exclusivas para administrar el registro:

```env
ADMIN_USERNAME=tu_usuario_admin
ADMIN_PASSWORD=una_contraseña_aleatoria_larga_de_16_caracteres_o_más
```

Inicia el servidor y abre <http://localhost:8000/admin>. El panel permite crear clientes, añadir y quitar callbacks, rotar el secreto y revocar clientes. Las callbacks externas deben usar HTTPS; HTTP solo se acepta para `localhost`, `127.0.0.1` y `::1` durante desarrollo. No admite parámetros query ni fragmentos en las URI registradas.

Al crear un cliente se generan `client_id` y `client_secret`. El secreto se muestra solo en esa respuesta y se almacena en SQLite como hash PBKDF2; guárdalo inmediatamente en el entorno del backend cliente. Si lo pierdes, rótalo. El panel no expone los secretos anteriores. Los cambios de cliente/callback se guardan en `clients.sqlite3` (o en la ruta de `CLIENTS_DB_PATH`); el archivo está excluido de Git.

El acceso al panel exige contraseña y un código TOTP de una app Authenticator. En el primer acceso, después de la contraseña, escanea el QR y confirma con un código de seis dígitos; los siguientes accesos pedirán el código actual. El secreto TOTP se cifra en SQLite con una clave derivada de `SESSION_SECRET`. Conserva ese valor aleatorio y no lo cambies sin reconfigurar TOTP. Las sesiones antiguas sin segundo factor dejan de autorizar el panel.

El panel también usa CSRF tokens, cookies firmadas y un límite básico de intentos por IP. Si pierdes el dispositivo TOTP, detén el servidor y ejecuta `python reset_admin_totp.py`; tras confirmar el restablecimiento, vuelve a entrar con `ADMIN_USERNAME` y `ADMIN_PASSWORD` para enrolar el nuevo dispositivo. Los datos de clientes permanecen en la base.

Para un despliegue público, usa HTTPS, contraseñas únicas y fuertes, restringe `/admin` por red o VPN si puedes, y usa un almacén compartido de sesiones/rate limits al escalar a varias instancias.

## Integración desde un backend cliente privado

El secreto de cliente se usa solo en el backend privado, nunca en JavaScript del navegador ni en una app descargable. Todos los endpoints de clientes requieren HTTPS en producción. Después de crear el cliente y registrar su callback en `/admin`, el backend cliente puede iniciar el flujo así:

```python
import secrets
import requests

API = "https://minecraft-api.ejemplo.com"
CLIENT_ID = "cl_id_generado_en_el_panel"
CLIENT_SECRET = "secreto_mostrado_una_vez_en_el_panel"
CALLBACK = "https://mi-servicio.ejemplo.com/auth/minecraft/callback"

# Guardar CLIENT_SECRET como variable secreta del backend cliente.
client_token = requests.post(
    f"{API}/oauth/token",
    auth=(CLIENT_ID, CLIENT_SECRET),
    data={"grant_type": "client_credentials"},
    timeout=15,
).json()["access_token"]

# Crear state por sesión de usuario y guardarlo en la sesión del backend cliente.
state = secrets.token_urlsafe(32)
url_inicio = requests.post(
    f"{API}/v1/authorizations",
    headers={"Authorization": f"Bearer {client_token}"},
    json={"callback_uri": CALLBACK, "state": state},
    timeout=15,
).json()["authorization_url"]

# Redirigir el navegador de ese usuario a url_inicio.
```

Microsoft vuelve al callback fijo de este proyecto. Tras autenticar y consultar Minecraft, el navegador vuelve al callback registrado del cliente con `code` y `state`; el perfil y los tokens nunca se ponen en esa URL. El callback del backend cliente compara `state` con el valor que guardó para esa sesión y luego canjea el código:

```python
perfil = requests.post(
    f"{API}/v1/authorizations/exchange",
    headers={"Authorization": f"Bearer {client_token}"},
    json={"code": codigo_recibido, "state": state_recibido},
    timeout=15,
).json()
# perfil: {"edition": "java", "name": "...", "uuid": "..."}
```

El código final expira en 90 segundos, está ligado al cliente y al `state`, y solo puede canjearse una vez. El token de cliente dura 10 minutos; se guarda como hash y se invalida al revocar el cliente o rotar su secreto. El estado temporal del flujo Microsoft vive en memoria en esta versión, por lo que el ejemplo requiere una instancia/proceso único y un reinicio cancela inicios de sesión pendientes. Antes de escalar, muévelo a almacenamiento compartido protegido.

## Modo de desarrollo sin Microsoft

Para probar el intercambio completo sin abrir Microsoft ni llamar a Xbox/Minecraft, cambia en `.env`:

```env
AUTH_MODE=development
MOCK_PROFILE_NAME=PruebaMinecraft
MOCK_PROFILE_UUID=12345678-1234-4234-8234-123456789abc
```

Reinicia la API. El resto del flujo de cliente es el mismo: token del cliente, verificación de callback registrada, devolución de código temporal y canje autenticado. La URL de autorización será local (`/dev/authorize`) y usará el nombre/UUID ficticios configurados. También puedes abrir `/auth/login` para probar el modo de sesión de navegador. En modo de desarrollo no se requieren `MICROSOFT_CLIENT_ID` ni `MICROSOFT_CLIENT_SECRET`.

`AUTH_MODE=development` solo arranca si `PUBLIC_BASE_URL` es localhost o una dirección loopback y además rechaza conexiones que no procedan de una IP loopback. Para el flujo real usa `AUTH_MODE=microsoft`; ese es también el valor predeterminado.

## Cliente falso local (puerto 8001)

El archivo `fake_client.py` simula un backend cliente privado independiente. Para probar el flujo completo:

1. Arranca la API con `AUTH_MODE=development` en `http://127.0.0.1:8000`.
2. Abre <http://127.0.0.1:8000/admin>, inicia sesión y crea un cliente llamado, por ejemplo, `Fake local`.
3. Registra exactamente esta callback: `http://127.0.0.1:8001/callback`.
4. Copia el `client_id` y `client_secret` mostrados una sola vez a `DEMO_CLIENT_ID` y `DEMO_CLIENT_SECRET` en el `.env`. Genera también `DEMO_SESSION_SECRET` con una clave aleatoria de 32 caracteres o más.
5. Ejecuta `python fake_client.py` en otra terminal o desde otra configuración de PyCharm.
6. Abre <http://127.0.0.1:8001> y pulsa **Conectar con Minecraft**. Al terminar, el cliente muestra el perfil ficticio recibido mediante el código temporal.

El secreto del cliente de demostración permanece en el proceso/servidor del puerto 8001. El navegador solo ve la URL de autorización y el código de un solo uso que se canjea en el callback. No publiques los valores `DEMO_CLIENT_SECRET` ni `DEMO_SESSION_SECRET`.

## Instalar y ejecutar en Windows

En PowerShell, desde esta carpeta:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Rellena el Client ID, el Client Secret **Value**, `SESSION_SECRET` (una clave aleatoria independiente) y `PUBLIC_BASE_URL`. Para desarrollo local usa `http://localhost:8000`. Inicia el servidor:

```powershell
uvicorn webapp:app --reload
```

Abre <http://localhost:8000>, pulsa **Iniciar sesión con Microsoft**, completa la autorización y luego consulta <http://localhost:8000/api/me>. FastAPI ofrece documentación en <http://localhost:8000/docs>.

Puedes generar una clave de sesión aleatoria en PowerShell con:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
```

Pega el resultado en `SESSION_SECRET`. No reutilices el Client Secret como clave de sesión.

## Despliegue y seguridad

- En producción sirve la API detrás de HTTPS, define `PUBLIC_BASE_URL` con la URL HTTPS y usa `COOKIE_SECURE=true`.
- Conserva `.env` fuera de Git; `.gitignore` ya lo excluye. No compartas el Client Secret ni tokens.
- El navegador recibe una cookie firmada con el perfil público (nombre y UUID), nunca tokens de Microsoft o Minecraft. La cookie firmada no está cifrada.
- El ejemplo guarda temporalmente los datos OAuth pendientes en memoria. Usa un almacén compartido antes de escalar a varios procesos/instancias.
- Limita `CORS_ORIGINS` a tus frontends exactos. CORS no autentica al usuario; `/api/me` solo devuelve el perfil de la sesión autenticada.
- Minecraft debe autorizar el Client ID. Si falta el perfil, la API devuelve `404 no_minecraft_profile`; errores de proveedor devuelven `502` con código legible.

"""Restablecimiento manual del enrolamiento TOTP del administrador."""

from __future__ import annotations

from dotenv import load_dotenv


def main() -> int:
    load_dotenv()
    from admin_panel import database

    confirmation = input("Escribe RESET TOTP para borrar el enrolamiento actual: ").strip()
    if confirmation != "RESET TOTP":
        print("Cancelado; no se modificó la configuración.")
        return 1
    with database() as db:
        db.execute("DELETE FROM admin_totp WHERE singleton=1")
    print("TOTP restablecido. Arranca la API e inicia sesión con ADMIN_USERNAME/ADMIN_PASSWORD para enrolar otro dispositivo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

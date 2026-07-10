"""Llamadas REST a la API de Discord usadas por la web (sin gateway).

Usa el token del bot (secreto TOKEN, ya configurado para el bot) para:
- Consultar información de OAuth2 del usuario que inicia sesión.
- Consultar los roles del usuario en el servidor de Postulaciones.
- Enviar mensajes directos (MD) a los usuarios sobre el estado de su postulación.
"""

import os
import requests

API_BASE = "https://discord.com/api/v10"
BOT_TOKEN = os.environ.get("TOKEN")
CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
GUILD_ID = os.environ.get("DISCORD_GUILD_ID")
ADMIN_ROLE_ID = os.environ.get("DISCORD_ADMIN_ROLE_ID")


def _bot_headers() -> dict:
    return {"Authorization": f"Bot {BOT_TOKEN}"}


def exchange_code(code: str, redirect_uri: str) -> dict:
    """Intercambia el código de OAuth2 por un access token del usuario."""
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(f"{API_BASE}/oauth2/token", data=data, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_user_identity(access_token: str) -> dict:
    """Obtiene id/username/avatar del usuario autenticado (scope identify)."""
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{API_BASE}/users/@me", headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def user_has_admin_role(discord_id: int) -> bool:
    """Consulta (con el token del bot) si el usuario tiene el rol de admin en el servidor."""
    if not GUILD_ID or not ADMIN_ROLE_ID:
        return False
    try:
        resp = requests.get(
            f"{API_BASE}/guilds/{GUILD_ID}/members/{discord_id}",
            headers=_bot_headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            return False
        roles = resp.json().get("roles", [])
        return ADMIN_ROLE_ID in roles
    except requests.RequestException:
        return False


def fetch_public_user(discord_id: int) -> dict | None:
    """Obtiene datos públicos de un usuario por ID (para mostrarlo en paneles)."""
    try:
        resp = requests.get(f"{API_BASE}/users/{discord_id}", headers=_bot_headers(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except requests.RequestException:
        return None


def _open_dm_channel(discord_id: int) -> str | None:
    resp = requests.post(
        f"{API_BASE}/users/@me/channels",
        headers=_bot_headers(),
        json={"recipient_id": str(discord_id)},
        timeout=10,
    )
    if resp.status_code not in (200, 201):
        return None
    return resp.json().get("id")


def send_dm(discord_id: int, content: str | None = None, embed: dict | None = None) -> bool:
    """Envía un mensaje directo al usuario. Devuelve False si falla o tiene los MD cerrados."""
    try:
        channel_id = _open_dm_channel(discord_id)
        if not channel_id:
            return False
        payload = {}
        if content:
            payload["content"] = content
        if embed:
            payload["embeds"] = [embed]
        resp = requests.post(
            f"{API_BASE}/channels/{channel_id}/messages",
            headers=_bot_headers(),
            json=payload,
            timeout=10,
        )
        return resp.status_code in (200, 201)
    except requests.RequestException:
        return False


def avatar_url(discord_id: int, avatar_hash: str | None) -> str:
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.{ext}?size=128"
    default_index = (int(discord_id) >> 22) % 6
    return f"https://cdn.discordapp.com/embed/avatars/{default_index}.png"

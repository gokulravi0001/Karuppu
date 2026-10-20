"""Discord OAuth2 authentication and session helpers."""
import os
import json
import hmac
import hashlib
import base64
import time
import logging
from typing import Dict, Any, Optional, List
import aiohttp
from aiohttp import web
from src.config import bot_config

logger = logging.getLogger("security_bot.dashboard.auth")

DISCORD_API_BASE = "https://discord.com/api/v10"

class AuthManager:
    def __init__(self):
        self.client_id = os.getenv("CLIENT_ID", os.getenv("DISCORD_CLIENT_ID", ""))
        self.client_secret = os.getenv("CLIENT_SECRET", os.getenv("DISCORD_CLIENT_SECRET", ""))
        self.dashboard_url = os.getenv("DASHBOARD_URL", f"http://localhost:{bot_config.health_port}").rstrip("/")
        self.session_secret = os.getenv("SESSION_SECRET", "antigravity-secure-session-key-change-me").encode("utf-8")

    @property
    def redirect_uri(self) -> str:
        return f"{self.dashboard_url}/auth/callback"

    def get_oauth_url(self) -> str:
        """Generates Discord OAuth2 authorization URL."""
        import urllib.parse
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "identify guilds"
        }
        return f"https://discord.com/oauth2/authorize?{urllib.parse.urlencode(params)}"

    def sign_session(self, data: dict) -> str:
        """Serializes and HMAC-signs a session payload into a secure cookie string."""
        payload_bytes = json.dumps(data).encode("utf-8")
        sig = hmac.new(self.session_secret, payload_bytes, hashlib.sha256).hexdigest()
        raw = json.dumps({"payload": base64.b64encode(payload_bytes).decode("ascii"), "sig": sig})
        return base64.urlsafe_b64encode(raw.encode("ascii")).decode("ascii")

    def decode_session(self, cookie_val: str) -> Optional[dict]:
        """Validates signature and decodes session cookie."""
        try:
            raw = base64.urlsafe_b64decode(cookie_val.encode("ascii")).decode("ascii")
            container = json.loads(raw)
            payload_bytes = base64.b64decode(container["payload"].encode("ascii"))
            expected_sig = hmac.new(self.session_secret, payload_bytes, hashlib.sha256).hexdigest()
            if hmac.compare_digest(container["sig"], expected_sig):
                return json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            pass
        return None

    async def exchange_code(self, code: str) -> Optional[dict]:
        """Exchanges authorization code for an OAuth2 access token."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with aiohttp.ClientSession() as session:
            async with session.post(f"{DISCORD_API_BASE}/oauth2/token", data=data, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                text = await resp.text()
                logger.error("OAuth exchange failed (%d): %s", resp.status, text)
        return None

    async def fetch_user_info(self, access_token: str) -> Optional[dict]:
        """Fetches current user's profile (/users/@me)."""
        headers = {"Authorization": f"Bearer {access_token}"}
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{DISCORD_API_BASE}/users/@me", headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
        return None

    async def fetch_user_guilds(self, access_token: str) -> List[dict]:
        """Fetches guilds the user belongs to (/users/@me/guilds)."""
        headers = {"Authorization": f"Bearer {access_token}"}
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
        return []

auth_manager = AuthManager()

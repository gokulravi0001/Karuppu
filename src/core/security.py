"""Security utilities, developer authorization, API rate limiting, and CSRF protection."""
import os
import time
import hmac
import hashlib
import secrets
from collections import defaultdict, deque
from typing import Optional, Dict, Tuple, List, Union
from src.config import bot_config

class RateLimiter:
    """Sliding-window rate limiter for dashboard requests and API endpoints."""
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # client_id -> deque of request timestamps
        self._history: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, client_key: str) -> Tuple[bool, int]:
        """Checks if client is allowed to perform action. Returns (is_allowed, retry_after_seconds)."""
        now = time.time()
        q = self._history[client_key]
        cutoff = now - self.window_seconds

        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - q[0])) + 1
            return False, max(1, retry_after)

        q.append(now)
        return True, 0

    def reset(self, client_key: str) -> None:
        if client_key in self._history:
            del self._history[client_key]

class SecurityManager:
    """Centralized security manager for developer authentication, CSRF tokens, and permission checks."""
    def __init__(self):
        self.rate_limiter = RateLimiter(max_requests=40, window_seconds=60)
        self.api_rate_limiter = RateLimiter(max_requests=60, window_seconds=60)
        self._dev_ids = self._load_developer_ids()

    def _load_developer_ids(self) -> set:
        devs = set()
        if bot_config.owner_id:
            try:
                devs.add(int(bot_config.owner_id))
            except ValueError:
                pass

        env_devs = os.getenv("DEVELOPER_IDS", "")
        if env_devs:
            for d in env_devs.split(","):
                d = d.strip()
                if d.isdigit():
                    devs.add(int(d))
        return devs

    def is_developer(self, user_id: Union[int, str]) -> bool:
        """Returns True if the given Discord user ID is a recognized bot developer or global owner."""
        try:
            uid = int(user_id)
        except (ValueError, TypeError):
            return False
        return uid in self._dev_ids or (bot_config.owner_id and uid == int(bot_config.owner_id))

    def generate_csrf_token(self, session_id: str) -> str:
        """Generates a cryptographic HMAC-SHA256 CSRF token tied to a user session."""
        secret = os.getenv("SESSION_SECRET", "antigravity-secure-session-key").encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(8)
        message = f"{session_id}:{timestamp}:{nonce}".encode("utf-8")
        sig = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return f"{timestamp}:{nonce}:{sig}"

    def validate_csrf_token(self, session_id: str, token: str, max_age_seconds: int = 7200) -> bool:
        """Validates a CSRF token against session and timestamp expiration."""
        if not token or ":" not in token:
            return False
        parts = token.split(":")
        if len(parts) != 3:
            return False

        timestamp_str, nonce, sig = parts
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return False

        # Expiry check
        now = int(time.time())
        if now - timestamp > max_age_seconds or timestamp > now + 300:
            return False

        secret = os.getenv("SESSION_SECRET", "antigravity-secure-session-key").encode("utf-8")
        message = f"{session_id}:{timestamp_str}:{nonce}".encode("utf-8")
        expected_sig = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)

    @staticmethod
    def sanitize_input(text: Optional[str], max_length: int = 500) -> str:
        """Sanitizes user input string against HTML injection and excessive length."""
        if not text:
            return ""
        clean = str(text).strip()[:max_length]
        # Basic character escape for HTML tags
        clean = clean.replace("<", "&lt;").replace(">", "&gt;")
        return clean

security_manager = SecurityManager()

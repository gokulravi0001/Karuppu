"""Command cooldown engine supporting user-level, command-level, and guild-level rate limiting."""
import time
from collections import defaultdict
from typing import Dict, Tuple, Optional

class CooldownManager:
    """Tracks and enforces command cooldowns dynamically per user and guild."""
    def __init__(self, default_cooldown_seconds: float = 3.0):
        self.default_cooldown = default_cooldown_seconds
        # key: f"{guild_id}:{user_id}:{command_name}" -> last_executed_timestamp
        self._cooldowns: Dict[str, float] = defaultdict(float)

    def check_cooldown(
        self,
        guild_id: Optional[int],
        user_id: int,
        command_name: str,
        cooldown_seconds: Optional[float] = None
    ) -> Tuple[bool, float]:
        """
        Checks if a command invocation is on cooldown.
        Returns: (is_on_cooldown, remaining_seconds)
        """
        duration = cooldown_seconds if cooldown_seconds is not None else self.default_cooldown
        if duration <= 0:
            return False, 0.0

        key = f"{guild_id or 0}:{user_id}:{command_name}"
        now = time.time()
        last_time = self._cooldowns.get(key, 0.0)
        elapsed = now - last_time

        if elapsed < duration:
            remaining = duration - elapsed
            return True, remaining

        # Update last execution time
        self._cooldowns[key] = now
        return False, 0.0

    def reset_cooldown(self, guild_id: Optional[int], user_id: int, command_name: str) -> None:
        key = f"{guild_id or 0}:{user_id}:{command_name}"
        if key in self._cooldowns:
            del self._cooldowns[key]

cooldown_manager = CooldownManager(default_cooldown_seconds=3.0)

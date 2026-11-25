"""Centralized logging, error redaction, deduplication, and auto-maintenance monitor."""
import re
import time
import logging
import traceback
from collections import deque
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

# Sensitive credential patterns for redaction
_TOKEN_REGEX = re.compile(r"([A-Za-z0-9_\-]{24,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})")
_SECRET_KEYWORD_REGEX = re.compile(
    r"(token|secret|password|session_secret|client_secret|authorization|key)[\"']?\s*[:=]\s*[\"']?([^\"'\s&]+)",
    re.IGNORECASE
)

def scrub_sensitive_data(text: str) -> str:
    """Masks tokens, secrets, credentials, and API keys from error messages and logs."""
    if not isinstance(text, str):
        text = str(text)
    # Mask Discord tokens
    text = _TOKEN_REGEX.sub(r"[\1[:8]...REDACTED_TOKEN]", text)
    # Mask labeled secret keys
    def _mask_secret(match):
        key = match.group(1)
        return f"{key}='***REDACTED***'"
    text = _SECRET_KEYWORD_REGEX.sub(_mask_secret, text)
    return text

class RingBufferLogHandler(logging.Handler):
    """In-memory ring buffer holding recent structured log records for the dashboard."""
    def __init__(self, capacity: int = 500):
        super().__init__()
        self.capacity = capacity
        self.records: deque = deque(maxlen=capacity)
        self.recent_errors: deque = deque(maxlen=200)
        # Deduplication cache: key -> (timestamp, count)
        self._dedup_cache: Dict[str, Tuple[float, int]] = {}
        self.dedup_window: float = 15.0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = scrub_sensitive_data(self.format(record))
            tb_str = None
            err_type = None

            if record.exc_info and record.exc_info[0]:
                err_type = record.exc_info[0].__name__
                tb_lines = traceback.format_exception(*record.exc_info)
                tb_str = scrub_sensitive_data("".join(tb_lines))

            # Deduplication key
            dedup_key = f"{record.name}:{record.levelname}:{msg[:80]}"
            now = time.time()
            if dedup_key in self._dedup_cache:
                last_time, count = self._dedup_cache[dedup_key]
                if (now - last_time) < self.dedup_window:
                    self._dedup_cache[dedup_key] = (last_time, count + 1)
                    return  # Suppress duplicate spam
            self._dedup_cache[dedup_key] = (now, 1)

            entry: Dict[str, Any] = {
                "id": len(self.records) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": msg,
                "error_type": err_type,
                "traceback": tb_str,
                "guild_id": getattr(record, "guild_id", None),
                "guild_name": getattr(record, "guild_name", None),
                "command_name": getattr(record, "command_name", None),
                "user_id": getattr(record, "user_id", None)
            }

            self.records.append(entry)
            if record.levelno >= logging.ERROR:
                self.recent_errors.append(entry)
                # Feed error event to AutoMaintenanceMonitor
                auto_maintenance_monitor.record_error(entry)
        except Exception:
            self.handleError(record)

    def get_logs(
        self,
        level: Optional[str] = None,
        search: Optional[str] = None,
        guild_id: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Filters and returns buffered log records."""
        results = list(self.records)
        results.reverse()

        filtered = []
        for r in results:
            if level and r["level"].upper() != level.upper():
                continue
            if guild_id and r.get("guild_id") != guild_id:
                continue
            if search:
                s = search.lower()
                if (
                    s not in r["message"].lower()
                    and s not in r["logger"].lower()
                    and s not in str(r.get("error_type", "")).lower()
                ):
                    continue
            filtered.append(r)
            if len(filtered) >= limit:
                break
        return filtered


class AutoMaintenanceMonitor:
    """Monitors system-wide error spikes and automatically trips maintenance mode when thresholds are exceeded."""
    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.error_timestamps: deque = deque()
        self.is_tripped: bool = False
        self.tripped_at: Optional[str] = None
        self.trip_reason: Optional[str] = None
        self._bot = None

    def set_bot(self, bot) -> None:
        self._bot = bot

    def record_error(self, entry: Dict[str, Any]) -> None:
        """Records an error occurrence and checks if the auto-maintenance trip threshold is exceeded."""
        now = time.time()
        self.error_timestamps.append(now)

        # Purge timestamps outside the rolling window
        cutoff = now - self.window_seconds
        while self.error_timestamps and self.error_timestamps[0] < cutoff:
            self.error_timestamps.popleft()

        if len(self.error_timestamps) >= self.threshold and not self.is_tripped:
            self.trigger_maintenance(
                reason=f"Spike threshold exceeded: {len(self.error_timestamps)} critical errors within {self.window_seconds}s."
            )

    def trigger_maintenance(self, reason: str) -> None:
        """Trips maintenance mode across the bot and schedules DB state persistence."""
        self.is_tripped = True
        self.tripped_at = datetime.now(timezone.utc).isoformat()
        self.trip_reason = reason
        logging.getLogger("security_bot.auto_maintenance").critical(
            "⚠️ AUTO-MAINTENANCE TRIPPED! Reason: %s", reason
        )

        # Asynchronously persist to database and notify if event loop is running
        import asyncio
        from src.database import db

        async def _persist():
            try:
                await db.set_system_state(
                    key="maintenance_mode",
                    value="true",
                    updated_by="AutoMaintenanceSystem",
                    details=reason
                )
                await db.log_system_event(
                    severity="CRITICAL",
                    module="AutoMaintenance",
                    event_type="AUTO_MAINTENANCE_TRIPPED",
                    message=f"Automated maintenance mode engaged: {reason}",
                    raw_data={"error_spike_count": len(self.error_timestamps), "threshold": self.threshold}
                )
            except Exception as e:
                logging.getLogger("security_bot.auto_maintenance").error("Failed to persist auto-maintenance state: %s", e)

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_persist())
        except RuntimeError:
            pass

    def reset_maintenance(self, reset_by: str = "Admin") -> None:
        """Resets the auto-maintenance monitor trip switch."""
        self.is_tripped = False
        self.tripped_at = None
        self.trip_reason = None
        self.error_timestamps.clear()

        import asyncio
        from src.database import db

        async def _clear():
            try:
                await db.set_system_state(
                    key="maintenance_mode",
                    value="false",
                    updated_by=reset_by,
                    details="Maintenance mode cleared by developer."
                )
                await db.log_system_event(
                    severity="INFO",
                    module="AutoMaintenance",
                    event_type="AUTO_MAINTENANCE_RESET",
                    message=f"Maintenance mode manually reset by {reset_by}."
                )
            except Exception as e:
                logging.getLogger("security_bot.auto_maintenance").error("Failed to clear maintenance state: %s", e)

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_clear())
        except RuntimeError:
            pass

    def get_status(self) -> Dict[str, Any]:
        """Returns the current state and metrics of the auto-maintenance engine."""
        now = time.time()
        cutoff = now - self.window_seconds
        recent_count = sum(1 for t in self.error_timestamps if t >= cutoff)
        return {
            "is_tripped": self.is_tripped,
            "tripped_at": self.tripped_at,
            "trip_reason": self.trip_reason,
            "recent_error_count": recent_count,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds
        }

# Global logging ring buffer and auto-maintenance monitor singletons
ring_buffer_handler = RingBufferLogHandler(capacity=1000)
ring_buffer_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"))
auto_maintenance_monitor = AutoMaintenanceMonitor(threshold=10, window_seconds=60)

def attach_core_logger(root_logger_name: str = "security_bot") -> None:
    """Attaches the ring buffer handler to the specified logger namespace."""
    tgt_logger = logging.getLogger(root_logger_name)
    if ring_buffer_handler not in tgt_logger.handlers:
        tgt_logger.addHandler(ring_buffer_handler)

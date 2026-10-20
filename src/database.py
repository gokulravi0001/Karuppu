"""Database module for structured audit logging and owner bypass persistence."""
import os
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import aiosqlite

logger = logging.getLogger("security_bot.database")

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "audit.db")

class AuditDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    async def init_db(self) -> None:
        """Initializes SQLite tables for audit logs and owner bypasses."""
        async with aiosqlite.connect(self.db_path) as db:
            # Incidents table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    rule_triggered TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    evidence_snippet TEXT,
                    action_taken TEXT NOT NULL,
                    moderator_id INTEGER,
                    status TEXT DEFAULT 'OPEN'
                );
            """)

            # Dynamic owner bypasses table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dynamic_bypasses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL DEFAULT 0,
                    bypass_type TEXT NOT NULL, -- 'role', 'user', 'channel'
                    target_id INTEGER NOT NULL,
                    target_name TEXT,
                    added_by INTEGER NOT NULL,
                    added_at TEXT NOT NULL,
                    UNIQUE(guild_id, target_id)
                );
            """)

            # Per-guild settings table for public multi-server hosting
            await db.execute("""
                CREATE TABLE IF NOT EXISTS guild_settings (
                    guild_id INTEGER PRIMARY KEY,
                    alert_channel_id INTEGER,
                    dry_run INTEGER DEFAULT 1,
                    link_role_id INTEGER,
                    link_role_name TEXT,
                    media_role_id INTEGER,
                    media_role_name TEXT,
                    mic_role_id INTEGER,
                    mic_role_name TEXT,
                    archive_role_id INTEGER,
                    archive_role_name TEXT,
                    invite_role_id INTEGER,
                    invite_role_name TEXT,
                    chat_log_channel_id INTEGER,
                    voice_log_channel_id INTEGER,
                    member_log_channel_id INTEGER,
                    mod_log_channel_id INTEGER,
                    server_log_channel_id INTEGER
                );
            """)

            # Ensure columns exist in existing database tables (automatic migration)
            log_cols = [
                ("chat_log_channel_id", "INTEGER"),
                ("voice_log_channel_id", "INTEGER"),
                ("member_log_channel_id", "INTEGER"),
                ("mod_log_channel_id", "INTEGER"),
                ("server_log_channel_id", "INTEGER"),
            ]
            for col_name, col_type in log_cols:
                try:
                    await db.execute(f"ALTER TABLE guild_settings ADD COLUMN {col_name} {col_type};")
                except Exception:
                    pass  # Column already exists

            # Index for fast incident lookup
            await db.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON incidents(user_id);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp);")
            await db.commit()
            logger.info("Database initialized successfully at %s", self.db_path)

    @staticmethod
    def hash_evidence(evidence: str) -> str:
        """Creates a SHA-256 hash of message content to avoid persisting raw message text."""
        return hashlib.sha256(evidence.encode("utf-8", errors="ignore")).hexdigest()

    async def log_incident(
        self,
        guild_id: int,
        user_id: int,
        username: str,
        rule_triggered: str,
        confidence: str,
        raw_evidence: str,
        action_taken: str,
        moderator_id: Optional[int] = None
    ) -> int:
        """Records a security incident into the structured audit log."""
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_hash = self.hash_evidence(raw_evidence)
        # Redact evidence snippet to max 60 chars for privacy
        snippet = (raw_evidence[:60] + "...") if len(raw_evidence) > 60 else raw_evidence

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO incidents (
                    timestamp, guild_id, user_id, username,
                    rule_triggered, confidence, evidence_hash,
                    evidence_snippet, action_taken, moderator_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, guild_id, user_id, username,
                rule_triggered, confidence, evidence_hash,
                snippet, action_taken, moderator_id
            ))
            await db.commit()
            return cursor.lastrowid or 0

    async def update_incident_status(self, incident_id: int, status: str, moderator_id: int) -> None:
        """Updates the status of an incident (e.g., 'DISMISSED', 'ENFORCED')."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE incidents
                SET status = ?, moderator_id = ?
                WHERE id = ?
            """, (status, moderator_id, incident_id))
            await db.commit()

    async def get_guild_settings(self, guild_id: int) -> Dict[str, Any]:
        """Fetches settings for a specific guild."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
        return {}

    async def update_guild_role_gate(self, guild_id: int, gate_name: str, role_id: int, role_name: str) -> None:
        """Sets the required role for a specific gate in a guild (e.g. links, media, mic)."""
        valid_gates = {
            "links": ("link_role_id", "link_role_name"),
            "media": ("media_role_id", "media_role_name"),
            "mic": ("mic_role_id", "mic_role_name"),
            "archives": ("archive_role_id", "archive_role_name"),
            "invites": ("invite_role_id", "invite_role_name")
        }
        if gate_name not in valid_gates:
            raise ValueError(f"Unknown gate: {gate_name}")

        id_col, name_col = valid_gates[gate_name]
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(f"""
                INSERT INTO guild_settings (guild_id, {id_col}, {name_col})
                VALUES (?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    {id_col} = excluded.{id_col},
                    {name_col} = excluded.{name_col};
            """, (guild_id, role_id, role_name))
            await db.commit()

    async def set_alert_channel(self, guild_id: int, channel_id: int) -> None:
        """Sets the mod alert channel for a guild."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, alert_channel_id)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET alert_channel_id = excluded.alert_channel_id;
            """, (guild_id, channel_id))
            await db.commit()

    async def set_log_channel(self, guild_id: int, log_category: str, channel_id: int) -> None:
        """Sets a specialized log channel (chat, voice, member, mod, server)."""
        valid_cols = {
            "chat": "chat_log_channel_id",
            "voice": "voice_log_channel_id",
            "member": "member_log_channel_id",
            "mod": "mod_log_channel_id",
            "server": "server_log_channel_id"
        }
        if log_category not in valid_cols:
            raise ValueError(f"Unknown log category: {log_category}")

        col = valid_cols[log_category]
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(f"""
                INSERT INTO guild_settings (guild_id, {col})
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET {col} = excluded.{col};
            """, (guild_id, channel_id))
            await db.commit()

    async def set_guild_dry_run(self, guild_id: int, dry_run: bool) -> None:
        """Sets the dry-run status for a specific guild."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, dry_run)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET dry_run = excluded.dry_run;
            """, (guild_id, 1 if dry_run else 0))
            await db.commit()

    async def add_dynamic_bypass(self, bypass_type: str, target_id: int, target_name: str, added_by: int, guild_id: int = 0) -> bool:
        """Inserts an owner-authorized bypass entry for a specific guild."""
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO dynamic_bypasses (guild_id, bypass_type, target_id, target_name, added_by, added_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (guild_id, bypass_type, target_id, target_name, added_by, timestamp))
                await db.commit()
                return True
        except Exception as e:
            logger.error("Failed to add dynamic bypass: %s", e)
            return False

    async def remove_dynamic_bypass(self, target_id: int, guild_id: int = 0) -> bool:
        """Removes an owner-authorized bypass entry."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                if guild_id:
                    cursor = await db.execute("DELETE FROM dynamic_bypasses WHERE target_id = ? AND guild_id = ?", (target_id, guild_id))
                else:
                    cursor = await db.execute("DELETE FROM dynamic_bypasses WHERE target_id = ?", (target_id,))
                await db.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error("Failed to remove dynamic bypass: %s", e)
            return False

    async def get_all_bypasses(self, guild_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieves dynamically registered owner bypasses for a guild."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if guild_id:
                async with db.execute("SELECT * FROM dynamic_bypasses WHERE guild_id = ? OR guild_id = 0 ORDER BY added_at DESC", (guild_id,)) as cursor:
                    rows = await cursor.fetchall()
            else:
                async with db.execute("SELECT * FROM dynamic_bypasses ORDER BY added_at DESC") as cursor:
                    rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def prune_old_records(self, retention_days: int = 30) -> int:
        """Prunes incident logs older than retention period for privacy compliance."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("DELETE FROM incidents WHERE timestamp < ?", (cutoff,))
            await db.commit()
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info("Pruned %d audit logs older than %d days", deleted, retention_days)
            return deleted

# Singleton database instance
db = AuditDatabase()

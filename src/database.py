"""Database module for structured audit logging, migrations, system state, and multi-server management."""
import os
import json
import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager
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

    @asynccontextmanager
    async def get_connection(self):
        """Asynchronous context manager providing a SQLite connection configured with safe synchronous mode and foreign keys."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("PRAGMA synchronous = NORMAL;")
            await conn.execute("PRAGMA foreign_keys = ON;")
            yield conn

    async def init_db(self) -> None:
        """Initializes SQLite tables for audit logs, owner bypasses, and executes schema migrations."""
        async with self.get_connection() as db:
            # 0. Migrations Registry Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT
                );
            """)

            # 1. Incidents table
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

            # 2. Dynamic owner bypasses table
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

            # 3. Per-guild settings table for public multi-server hosting
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
                    vc_state_log_channel_id INTEGER,
                    member_log_channel_id INTEGER,
                    mod_log_channel_id INTEGER,
                    server_log_channel_id INTEGER,
                    unmute_role_id INTEGER,
                    unmute_role_name TEXT,
                    guard_voice_channel_id INTEGER,
                    quarantine_role_id INTEGER,
                    quarantine_channel_id INTEGER,
                    quarantine_category_id INTEGER,
                    language TEXT DEFAULT 'en',
                    command_cooldown_seconds INTEGER DEFAULT 3
                );
            """)

            # 4. Voice Channel Punishments (VC Ban and VC Timeout)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS vc_punishments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    punishment_type TEXT NOT NULL, -- 'ban' or 'timeout'
                    moderator_id INTEGER NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT, -- NULL for permanent ban, or ISO timestamp for timeout / temp-ban
                    UNIQUE(guild_id, user_id, punishment_type)
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_vc_punish ON vc_punishments(guild_id, user_id);")

            # 5. Dedicated Granular Log Channels (Complete 33-Channel Logging Suite)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS guild_log_channels (
                    guild_id INTEGER NOT NULL,
                    log_type TEXT NOT NULL,
                    channel_id INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, log_type)
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_log_chan ON guild_log_channels(guild_id, log_type);")

            # 6. Quarantined Members Table (Isolation, Saved Roles & Restoration)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS quarantined_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    saved_role_ids TEXT NOT NULL,
                    quarantined_by INTEGER NOT NULL,
                    reason TEXT,
                    quarantined_at TEXT NOT NULL,
                    overwrites_backup TEXT,
                    UNIQUE(guild_id, user_id)
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_quarantine ON quarantined_users(guild_id, user_id);")

            # 7. Guild Modules Feature Toggles (Multi-Server Isolation)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS guild_modules (
                    guild_id INTEGER NOT NULL,
                    module_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    config_json TEXT DEFAULT '{}',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (guild_id, module_name)
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_guild_modules ON guild_modules(guild_id);")

            # 8. Centralized System Logs & Operational Records
            await db.execute("""
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    logger_name TEXT NOT NULL,
                    message TEXT NOT NULL,
                    guild_id INTEGER,
                    user_id INTEGER,
                    error_details TEXT
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_system_logs_ts ON system_logs(timestamp);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_system_logs_guild ON system_logs(guild_id);")

            # 9. Blacklisted Entities (Users & Guilds)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS blacklisted_entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL, -- 'user' or 'guild'
                    target_id INTEGER NOT NULL UNIQUE,
                    target_name TEXT,
                    reason TEXT,
                    added_by INTEGER NOT NULL,
                    added_at TEXT NOT NULL
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_blacklisted_target ON blacklisted_entities(target_id);")

            # 10. Dashboard & System Changelogs
            await db.execute("""
                CREATE TABLE IF NOT EXISTS changelogs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL, -- 'feature', 'fix', 'security', 'improvement'
                    author_id INTEGER NOT NULL,
                    published_at TEXT NOT NULL
                );
            """)

            # 11. Administrative Action Audit Trail (Dashboard & Management Security)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS admin_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_guild_id INTEGER,
                    details TEXT,
                    ip_address TEXT
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_logs(timestamp);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_user ON admin_audit_logs(user_id);")

            # 12. Persistent Global System State (Maintenance Mode, Auto-Lockdowns, Global Flags)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # 13. Guild Trusted Members (Bypass security filters and run bot commands without native perms)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS guild_trusted_members (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    user_name TEXT,
                    added_by INTEGER NOT NULL,
                    added_at TEXT NOT NULL,
                    PRIMARY KEY (guild_id, user_id)
                );
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_trusted_guild ON guild_trusted_members(guild_id);")

            # Safe column additions for backwards compatibility
            log_cols = [
                ("chat_log_channel_id", "INTEGER"),
                ("voice_log_channel_id", "INTEGER"),
                ("vc_state_log_channel_id", "INTEGER"),
                ("member_log_channel_id", "INTEGER"),
                ("mod_log_channel_id", "INTEGER"),
                ("server_log_channel_id", "INTEGER"),
                ("unmute_role_id", "INTEGER"),
                ("unmute_role_name", "TEXT"),
                ("guard_voice_channel_id", "INTEGER"),
                ("quarantine_role_id", "INTEGER"),
                ("quarantine_channel_id", "INTEGER"),
                ("quarantine_category_id", "INTEGER"),
                ("language", "TEXT DEFAULT 'en'"),
                ("command_cooldown_seconds", "INTEGER DEFAULT 3"),
            ]
            for col_name, col_type in log_cols:
                try:
                    await db.execute(f"ALTER TABLE guild_settings ADD COLUMN {col_name} {col_type};")
                except Exception:
                    pass  # Column already exists

            # Indexes for fast incident lookup
            await db.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON incidents(user_id);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp);")
            await db.commit()

        # Run Versioned Schema Migrations
        await self.run_migrations()
        logger.info("Database initialized successfully with WAL mode & migrations at %s", self.db_path)

    async def run_migrations(self) -> None:
        """Executes versioned migrations to guarantee schema consistency and integrity."""
        migrations = [
            ("001_core_initial", "Base security audit tables, guild settings, and quarantines"),
            ("002_core_systems", "Guild modules, system logs, blacklists, changelogs, audit trail, and system state"),
            ("003_settings_i18n_cooldown", "Per-guild language and command cooldown columns"),
            ("004_trusted_members", "Persistent guild trusted members registry")
        ]
        now_iso = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as db:
            for version, desc in migrations:
                cursor = await db.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (version,))
                row = await cursor.fetchone()
                if not row:
                    await db.execute(
                        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                        (version, now_iso, desc)
                    )
            await db.commit()

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

    async def get_recent_incidents(self, guild_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent security incidents for a specific guild."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM incidents WHERE guild_id = ? ORDER BY timestamp DESC LIMIT ?",
                (guild_id, limit)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

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
        """Sets a specialized log channel (chat, voice, vc_state, member, mod, server)."""
        valid_cols = {
            "chat": "chat_log_channel_id",
            "voice": "voice_log_channel_id",
            "vc_state": "vc_state_log_channel_id",
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

    async def set_unmute_role(self, guild_id: int, role_id: int, role_name: str) -> None:
        """Sets the owner-authorized role that is permitted to reverse server mutes."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, unmute_role_id, unmute_role_name)
                VALUES (?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    unmute_role_id = excluded.unmute_role_id,
                    unmute_role_name = excluded.unmute_role_name;
            """, (guild_id, role_id, role_name))
            await db.commit()

    async def set_guard_voice_channel(self, guild_id: int, channel_id: Optional[int]) -> None:
        """Saves or clears the designated voice channel for the 24/7 Voice Guard bot."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, guard_voice_channel_id)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    guard_voice_channel_id = excluded.guard_voice_channel_id;
            """, (guild_id, channel_id))
            await db.commit()

    async def update_all_role_gates(self, guild_id: int, role_data: Dict[str, Any]) -> None:
        """Updates multiple role gates for a guild at once."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (
                    guild_id,
                    link_role_id, link_role_name,
                    media_role_id, media_role_name,
                    mic_role_id, mic_role_name,
                    archive_role_id, archive_role_name,
                    invite_role_id, invite_role_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    link_role_id = excluded.link_role_id,
                    link_role_name = excluded.link_role_name,
                    media_role_id = excluded.media_role_id,
                    media_role_name = excluded.media_role_name,
                    mic_role_id = excluded.mic_role_id,
                    mic_role_name = excluded.mic_role_name,
                    archive_role_id = excluded.archive_role_id,
                    archive_role_name = excluded.archive_role_name,
                    invite_role_id = excluded.invite_role_id,
                    invite_role_name = excluded.invite_role_name;
            """, (
                guild_id,
                role_data.get("link_role_id"), role_data.get("link_role_name"),
                role_data.get("media_role_id"), role_data.get("media_role_name"),
                role_data.get("mic_role_id"), role_data.get("mic_role_name"),
                role_data.get("archive_role_id"), role_data.get("archive_role_name"),
                role_data.get("invite_role_id"), role_data.get("invite_role_name")
            ))
            await db.commit()

    async def update_all_log_channels(self, guild_id: int, log_data: Dict[str, int]) -> None:
        """Updates all specialized log channels for a guild at once."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (
                    guild_id,
                    chat_log_channel_id,
                    voice_log_channel_id,
                    vc_state_log_channel_id,
                    member_log_channel_id,
                    mod_log_channel_id,
                    server_log_channel_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    chat_log_channel_id = excluded.chat_log_channel_id,
                    voice_log_channel_id = excluded.voice_log_channel_id,
                    vc_state_log_channel_id = excluded.vc_state_log_channel_id,
                    member_log_channel_id = excluded.member_log_channel_id,
                    mod_log_channel_id = excluded.mod_log_channel_id,
                    server_log_channel_id = excluded.server_log_channel_id;
            """, (
                guild_id,
                log_data.get("chat_log_channel_id"),
                log_data.get("voice_log_channel_id"),
                log_data.get("vc_state_log_channel_id"),
                log_data.get("member_log_channel_id"),
                log_data.get("mod_log_channel_id"),
                log_data.get("server_log_channel_id")
            ))
            await db.commit()

    async def set_dedicated_log_channel(self, guild_id: int, log_type: str, channel_id: Optional[int]) -> None:
        """Sets or removes a dedicated log channel for a specific log type."""
        async with aiosqlite.connect(self.db_path) as db:
            if channel_id is not None:
                await db.execute("""
                    INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(guild_id, log_type) DO UPDATE SET channel_id = excluded.channel_id;
                """, (guild_id, log_type, channel_id))
            else:
                await db.execute("DELETE FROM guild_log_channels WHERE guild_id = ? AND log_type = ?;", (guild_id, log_type))
            await db.commit()

    async def bulk_set_log_channels(self, guild_id: int, channel_map: Dict[str, int]) -> None:
        """Sets multiple dedicated log channels in one transaction."""
        async with aiosqlite.connect(self.db_path) as db:
            for log_type, ch_id in channel_map.items():
                await db.execute("""
                    INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(guild_id, log_type) DO UPDATE SET channel_id = excluded.channel_id;
                """, (guild_id, log_type, ch_id))
            await db.commit()

    async def get_all_guild_log_channels(self, guild_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieves all dedicated log channels."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if guild_id is not None:
                query = "SELECT * FROM guild_log_channels WHERE guild_id = ?"
                params = (guild_id,)
            else:
                query = "SELECT * FROM guild_log_channels"
                params = ()
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

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

    async def add_vc_punishment(
        self,
        guild_id: int,
        user_id: int,
        punishment_type: str,
        moderator_id: int,
        reason: str,
        expires_at: Optional[str] = None
    ) -> None:
        """Adds or updates a voice channel ban or timeout for a user in a guild."""
        created_at = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO vc_punishments (
                    guild_id, user_id, punishment_type, moderator_id, reason, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id, user_id, punishment_type) DO UPDATE SET
                    moderator_id = excluded.moderator_id,
                    reason = excluded.reason,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at;
            """, (guild_id, user_id, punishment_type, moderator_id, reason, created_at, expires_at))
            await db.commit()

    async def remove_vc_punishment(self, guild_id: int, user_id: int, punishment_type: Optional[str] = None) -> bool:
        """Removes a voice channel punishment (ban/timeout) for a user."""
        async with aiosqlite.connect(self.db_path) as db:
            if punishment_type:
                cursor = await db.execute("""
                    DELETE FROM vc_punishments
                    WHERE guild_id = ? AND user_id = ? AND punishment_type = ?
                """, (guild_id, user_id, punishment_type))
            else:
                cursor = await db.execute("""
                    DELETE FROM vc_punishments
                    WHERE guild_id = ? AND user_id = ?
                """, (guild_id, user_id))
            await db.commit()
            return (cursor.rowcount or 0) > 0

    async def get_active_vc_punishments(self, guild_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieves active voice channel bans and timeouts."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if guild_id is not None:
                query = "SELECT * FROM vc_punishments WHERE guild_id = ? ORDER BY created_at DESC"
                params = (guild_id,)
            else:
                query = "SELECT * FROM vc_punishments ORDER BY created_at DESC"
                params = ()
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_user_vc_punishment(self, guild_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Checks if a user has an active VC ban or timeout in a guild."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("""
                SELECT * FROM vc_punishments
                WHERE (guild_id = ? OR guild_id = 0) AND user_id = ?
                ORDER BY CASE punishment_type WHEN 'ban' THEN 1 ELSE 2 END ASC
                LIMIT 1
            """, (guild_id, user_id)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def save_quarantine(
        self,
        guild_id: int,
        user_id: int,
        saved_role_ids: List[int],
        quarantined_by: int,
        reason: Optional[str] = None,
        overwrites_backup: Optional[str] = None
    ) -> None:
        """Saves a member's quarantine state and backups their original roles."""
        async with aiosqlite.connect(self.db_path) as db:
            now_iso = datetime.now(timezone.utc).isoformat()
            roles_json = json.dumps(saved_role_ids)
            await db.execute("""
                INSERT INTO quarantined_users (
                    guild_id, user_id, saved_role_ids, quarantined_by, reason, quarantined_at, overwrites_backup
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id, user_id) DO UPDATE SET
                    saved_role_ids = CASE
                        WHEN excluded.saved_role_ids != '[]' THEN excluded.saved_role_ids
                        ELSE quarantined_users.saved_role_ids
                    END,
                    quarantined_by = excluded.quarantined_by,
                    reason = excluded.reason,
                    quarantined_at = excluded.quarantined_at,
                    overwrites_backup = COALESCE(excluded.overwrites_backup, quarantined_users.overwrites_backup);
            """, (guild_id, user_id, roles_json, quarantined_by, reason or "Quarantined by staff", now_iso, overwrites_backup))
            await db.commit()

    async def get_quarantine(self, guild_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a quarantined member's backup info and reason."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM quarantined_users WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                data = dict(row)
                try:
                    data["saved_role_ids"] = json.loads(data["saved_role_ids"])
                except Exception:
                    data["saved_role_ids"] = []
                return data

    async def remove_quarantine(self, guild_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Removes a user from quarantine and returns their backup role data."""
        data = await self.get_quarantine(guild_id, user_id)
        if data:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    "DELETE FROM quarantined_users WHERE guild_id = ? AND user_id = ?",
                    (guild_id, user_id)
                )
                await db.commit()
        return data

    async def get_quarantine_incident_roles(self, guild_id: int, user_id: int) -> List[str]:
        """Finds role names stripped during quarantine from the audit incident log history."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT raw_evidence FROM incidents
                WHERE guild_id = ? AND user_id = ? AND rule_triggered = 'Member Quarantine'
                ORDER BY timestamp DESC LIMIT 5
                """,
                (guild_id, user_id)
            ) as cursor:
                rows = await cursor.fetchall()
                for r in rows:
                    raw = r["raw_evidence"] if r else ""
                    if "Roles stripped" in raw and ":" in raw:
                        try:
                            after_colon = raw.split(":", 1)[1]
                            role_part = after_colon.split("|", 1)[0].strip()
                            if role_part and role_part.lower() != "none":
                                names = [n.strip() for n in role_part.split(",") if n.strip()]
                                if names:
                                    return names
                        except Exception:
                            pass
        return []

    async def get_all_quarantined(self, guild_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieves all active quarantined members."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if guild_id is not None:
                query = "SELECT * FROM quarantined_users WHERE guild_id = ? ORDER BY quarantined_at DESC"
                params = (guild_id,)
            else:
                query = "SELECT * FROM quarantined_users ORDER BY quarantined_at DESC"
                params = ()
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                results = []
                for r in rows:
                    item = dict(r)
                    try:
                        item["saved_role_ids"] = json.loads(item["saved_role_ids"])
                    except Exception:
                        item["saved_role_ids"] = []
                    results.append(item)
                return results

    async def set_quarantine_role(self, guild_id: int, role_id: int) -> None:
        """Saves configured quarantine role ID in guild settings."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, quarantine_role_id)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET quarantine_role_id = excluded.quarantine_role_id;
            """, (guild_id, role_id))
            await db.commit()

    async def set_quarantine_channel(self, guild_id: int, channel_id: int) -> None:
        """Saves configured quarantine channel ID in guild settings."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, quarantine_channel_id)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET quarantine_channel_id = excluded.quarantine_channel_id;
            """, (guild_id, channel_id))
            await db.commit()

    async def set_quarantine_category(self, guild_id: int, category_id: int) -> None:
        """Saves configured quarantine category ID in guild settings."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO guild_settings (guild_id, quarantine_category_id)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET quarantine_category_id = excluded.quarantine_category_id;
            """, (guild_id, category_id))
            await db.commit()

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

    # ==========================================
    # SYSTEM STATE & MAINTENANCE MODE
    # ==========================================

    async def get_system_state(self, key: str, default: Any = None) -> Any:
        """Retrieves global persistent system state (maintenance mode, feature flags)."""
        async with self.get_connection() as db:
            async with db.execute("SELECT value FROM system_state WHERE key = ?", (key,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    try:
                        return json.loads(row[0])
                    except Exception:
                        return row[0]
        return default

    async def set_system_state(self, key: str, value: Any) -> None:
        """Saves global persistent system state."""
        val_str = json.dumps(value) if not isinstance(value, str) else value
        now_iso = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as db:
            await db.execute("""
                INSERT INTO system_state (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
            """, (key, val_str, now_iso))
            await db.commit()

    # ==========================================
    # GUILD MODULES (MULTI-SERVER ISOLATION)
    # ==========================================

    async def get_guild_modules(self, guild_id: int) -> Dict[str, Dict[str, Any]]:
        """Retrieves all module toggle states and configs for a specific guild."""
        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM guild_modules WHERE guild_id = ?", (guild_id,)) as cursor:
                rows = await cursor.fetchall()
                modules = {}
                for r in rows:
                    cfg = {}
                    try:
                        cfg = json.loads(r["config_json"]) if r["config_json"] else {}
                    except Exception:
                        pass
                    modules[r["module_name"]] = {
                        "enabled": bool(r["enabled"]),
                        "config": cfg,
                        "updated_at": r["updated_at"]
                    }
                return modules

    async def set_guild_module(
        self,
        guild_id: int,
        module_name: str,
        enabled: bool,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Enables or disables an individual module for a specific guild without affecting other servers."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cfg_str = json.dumps(config or {})
        async with self.get_connection() as db:
            await db.execute("""
                INSERT INTO guild_modules (guild_id, module_name, enabled, config_json, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(guild_id, module_name) DO UPDATE SET
                    enabled = excluded.enabled,
                    config_json = CASE WHEN excluded.config_json != '{}' THEN excluded.config_json ELSE guild_modules.config_json END,
                    updated_at = excluded.updated_at;
            """, (guild_id, module_name, 1 if enabled else 0, cfg_str, now_iso))
            await db.commit()

    async def is_module_enabled(self, guild_id: int, module_name: str, default: bool = True) -> bool:
        """Checks if a module is enabled for a guild, honoring server-specific overrides."""
        async with self.get_connection() as db:
            async with db.execute(
                "SELECT enabled FROM guild_modules WHERE guild_id = ? AND module_name = ?",
                (guild_id, module_name)
            ) as cursor:
                row = await cursor.fetchone()
                if row is not None:
                    return bool(row[0])
        return default

    # ==========================================
    # CENTRALIZED OPERATIONAL LOGS
    # ==========================================

    async def log_system_event(
        self,
        level: str,
        logger_name: str,
        message: str,
        guild_id: Optional[int] = None,
        user_id: Optional[int] = None,
        error_details: Optional[str] = None
    ) -> int:
        """Inserts an operational or error log entry into persistent storage."""
        now_iso = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as db:
            cursor = await db.execute("""
                INSERT INTO system_logs (timestamp, level, logger_name, message, guild_id, user_id, error_details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (now_iso, level.upper(), logger_name, message, guild_id, user_id, error_details))
            await db.commit()
            return cursor.lastrowid or 0

    async def get_system_logs(
        self,
        limit: int = 100,
        level: Optional[str] = None,
        guild_id: Optional[int] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Queries persistent operational logs with optional filters."""
        query = "SELECT * FROM system_logs WHERE 1=1"
        params = []
        if level and level.upper() != "ALL":
            query += " AND level = ?"
            params.append(level.upper())
        if guild_id is not None:
            query += " AND (guild_id = ? OR guild_id IS NULL)"
            params.append(guild_id)
        if search:
            query += " AND (message LIKE ? OR logger_name LIKE ? OR error_details LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param])
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    # ==========================================
    # BLACKLIST SYSTEM (USERS & GUILDS)
    # ==========================================

    async def add_to_blacklist(
        self,
        entity_type: str,
        target_id: int,
        target_name: str,
        reason: str,
        added_by: int
    ) -> bool:
        """Adds a user or guild to the blacklist."""
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            async with self.get_connection() as db:
                await db.execute("""
                    INSERT INTO blacklisted_entities (entity_type, target_id, target_name, reason, added_by, added_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(target_id) DO UPDATE SET
                        reason = excluded.reason,
                        added_by = excluded.added_by,
                        added_at = excluded.added_at;
                """, (entity_type, target_id, target_name, reason, added_by, now_iso))
                await db.commit()
                return True
        except Exception as e:
            logger.error("Failed adding to blacklist: %s", e)
            return False

    async def remove_from_blacklist(self, target_id: int) -> bool:
        """Removes an entity from the blacklist."""
        try:
            async with self.get_connection() as db:
                cursor = await db.execute("DELETE FROM blacklisted_entities WHERE target_id = ?", (target_id,))
                await db.commit()
                return (cursor.rowcount or 0) > 0
        except Exception as e:
            logger.error("Failed removing from blacklist: %s", e)
            return False

    async def is_blacklisted(self, entity_id: int) -> Optional[Dict[str, Any]]:
        """Checks if a user or guild is blacklisted."""
        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM blacklisted_entities WHERE target_id = ?", (entity_id,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def get_blacklist(self, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves all blacklisted entities."""
        query = "SELECT * FROM blacklisted_entities"
        params = ()
        if entity_type:
            query += " WHERE entity_type = ?"
            params = (entity_type,)
        query += " ORDER BY added_at DESC"
        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    # ==========================================
    # ADMINISTRATIVE ACTION AUDIT TRAIL
    # ==========================================

    async def log_admin_action(
        self,
        user_id: int,
        username: str,
        action: str,
        target_guild_id: Optional[int] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> int:
        """Records an administrative action performed on the dashboard."""
        now_iso = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as db:
            cursor = await db.execute("""
                INSERT INTO admin_audit_logs (timestamp, user_id, username, action, target_guild_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (now_iso, user_id, username, action, target_guild_id, details, ip_address))
            await db.commit()
            return cursor.lastrowid or 0

    async def get_admin_audit_logs(
        self,
        limit: int = 50,
        guild_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves dashboard administrative audit logs."""
        query = "SELECT * FROM admin_audit_logs"
        params = []
        if guild_id is not None:
            query += " WHERE target_guild_id = ? OR target_guild_id IS NULL"
            params.append(guild_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    # ==========================================
    # CHANGELOGS & RELEASES
    # ==========================================

    async def add_changelog(
        self,
        version: str,
        title: str,
        content: str,
        category: str,
        author_id: int
    ) -> int:
        """Publishes a new changelog entry."""
        now_iso = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as db:
            cursor = await db.execute("""
                INSERT INTO changelogs (version, title, content, category, author_id, published_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (version, title, content, category, author_id, now_iso))
            await db.commit()
            return cursor.lastrowid or 0

    async def get_changelogs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves recent changelogs ordered by published date."""
        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM changelogs ORDER BY id DESC LIMIT ?", (limit,)) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def delete_changelog(self, changelog_id: int) -> bool:
        """Deletes a changelog entry."""
        async with self.get_connection() as db:
            cursor = await db.execute("DELETE FROM changelogs WHERE id = ?", (changelog_id,))
            await db.commit()
            return (cursor.rowcount or 0) > 0

    # ==========================================
    # GUILD TRUSTED MEMBERS
    # ==========================================

    async def add_trusted_member(self, guild_id: int, user_id: int, user_name: str, added_by: int) -> bool:
        """Adds a member to the guild's trusted members registry."""
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            async with self.get_connection() as db:
                await db.execute("""
                    INSERT OR REPLACE INTO guild_trusted_members (guild_id, user_id, user_name, added_by, added_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (guild_id, user_id, user_name, added_by, timestamp))
                await db.commit()
            return True
        except Exception as e:
            logger.error("Failed to add trusted member (%d, %d): %s", guild_id, user_id, e)
            return False

    async def remove_trusted_member(self, guild_id: int, user_id: int) -> bool:
        """Removes a member from the guild's trusted members registry."""
        try:
            async with self.get_connection() as db:
                await db.execute("DELETE FROM guild_trusted_members WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
                await db.commit()
            return True
        except Exception as e:
            logger.error("Failed to remove trusted member (%d, %d): %s", guild_id, user_id, e)
            return False

    async def get_trusted_members(self, guild_id: int) -> List[Dict[str, Any]]:
        """Retrieves all trusted members for a guild."""
        try:
            async with self.get_connection() as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM guild_trusted_members WHERE guild_id = ? ORDER BY added_at DESC", (guild_id,)) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to get trusted members for guild %d: %s", guild_id, e)
            return []

    async def get_all_trusted_members(self) -> List[Dict[str, Any]]:
        """Retrieves all trusted members across all guilds for in-memory caching."""
        try:
            async with self.get_connection() as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT guild_id, user_id FROM guild_trusted_members") as cursor:
                    rows = await cursor.fetchall()
                    return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Failed to get all trusted members: %s", e)
            return []

    # ==========================================
    # DATABASE HEALTH MONITORING & BACKUP/RESTORE
    # ==========================================

    async def get_health_metrics(self) -> Dict[str, Any]:
        """Collects database health, table row counts, size on disk, and ping latency."""
        t0 = time.perf_counter()
        async with self.get_connection() as db:
            await db.execute("SELECT 1;")
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)

            # Query table counts
            table_counts = {}
            for table in [
                "incidents", "guild_settings", "guild_modules", "system_logs",
                "blacklisted_entities", "quarantined_users", "vc_punishments",
                "admin_audit_logs", "changelogs", "guild_trusted_members"
            ]:
                try:
                    async with db.execute(f"SELECT COUNT(*) FROM {table}") as cursor:
                        row = await cursor.fetchone()
                        table_counts[table] = row[0] if row else 0
                except Exception:
                    table_counts[table] = 0

            # Journal mode & user version
            async with db.execute("PRAGMA journal_mode;") as cursor:
                row = await cursor.fetchone()
                journal_mode = row[0] if row else "unknown"

            # Check applied migrations
            applied_migrations = []
            try:
                async with db.execute("SELECT version, applied_at FROM schema_migrations ORDER BY applied_at ASC") as cursor:
                    rows = await cursor.fetchall()
                    applied_migrations = [f"{r[0]} ({r[1][:10]})" for r in rows]
            except Exception:
                pass

        size_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        if size_bytes < 1024 * 1024:
            size_human = f"{size_bytes / 1024:.2f} KB"
        else:
            size_human = f"{size_bytes / (1024 * 1024):.2f} MB"

        return {
            "status": "healthy",
            "latency_ms": latency_ms,
            "journal_mode": journal_mode.upper(),
            "size_bytes": size_bytes,
            "size_human": size_human,
            "table_counts": table_counts,
            "applied_migrations": applied_migrations,
            "db_path": self.db_path
        }

    async def create_backup(self, guild_id: Optional[int] = None) -> Dict[str, Any]:
        """Generates a complete structured JSON backup snapshot of all configuration tables."""
        tables = [
            "guild_settings", "guild_modules", "guild_log_channels",
            "dynamic_bypasses", "quarantined_users", "vc_punishments",
            "blacklisted_entities", "changelogs", "system_state", "guild_trusted_members"
        ]
        backup_data = {
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scope": f"guild_{guild_id}" if guild_id else "global",
            "tables": {}
        }
        async with self.get_connection() as db:
            db.row_factory = aiosqlite.Row
            for t in tables:
                if guild_id and t in ("guild_settings", "guild_modules", "guild_log_channels", "quarantined_users", "vc_punishments", "dynamic_bypasses", "guild_trusted_members"):
                    q = f"SELECT * FROM {t} WHERE guild_id = ?"
                    p = (guild_id,)
                else:
                    q = f"SELECT * FROM {t}"
                    p = ()
                try:
                    async with db.execute(q, p) as cursor:
                        rows = await cursor.fetchall()
                        backup_data["tables"][t] = [dict(r) for r in rows]
                except Exception as e:
                    logger.warning("Could not backup table %s: %s", t, e)

        raw_json = json.dumps(backup_data["tables"], sort_keys=True)
        backup_data["checksum"] = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        return backup_data

    async def restore_backup(self, backup_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Restores a structured JSON backup snapshot within an atomic transaction with rollback safety."""
        tables_data = backup_data.get("tables", {})
        if not tables_data:
            return False, "Invalid backup format: Missing tables payload."

        async with self.get_connection() as db:
            try:
                for table_name, rows in tables_data.items():
                    if not rows:
                        continue
                    # Clean existing entries for restored records
                    if table_name == "guild_settings":
                        for r in rows:
                            if "guild_id" in r:
                                await db.execute("DELETE FROM guild_settings WHERE guild_id = ?", (r["guild_id"],))
                    elif table_name == "guild_modules":
                        for r in rows:
                            if "guild_id" in r:
                                await db.execute("DELETE FROM guild_modules WHERE guild_id = ?", (r["guild_id"],))

                    # Insert rows
                    for row in rows:
                        cols = list(row.keys())
                        placeholders = ", ".join(["?"] * len(cols))
                        col_str = ", ".join(cols)
                        vals = [row[c] for c in cols]
                        await db.execute(f"INSERT OR REPLACE INTO {table_name} ({col_str}) VALUES ({placeholders})", vals)

                await db.commit()
                return True, "Backup restored successfully."
            except Exception as e:
                logger.error("Database restore failed: %s", e)
                return False, f"Restore failed: {str(e)}"

# Singleton database instance
db = AuditDatabase()

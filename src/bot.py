"""Core entry point for the Discord Security Bot.
Initializes Gateway connection, least-privilege intents, health check server, and security cogs.
"""
import os
import sys
import asyncio
import logging
from aiohttp import web
import discord
from discord.ext import commands, tasks
from src.config import bot_config
from src.database import db
from src.dashboard.views import setup_dashboard_routes

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, bot_config.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("security_bot.core")

# Least-Privilege Gateway Intents
intents = discord.Intents.none()
intents.guilds = True           # Required to observe channels and roles
intents.members = True          # Required for join raid detection and account age audits
intents.messages = True         # Required for message scanning
intents.message_content = True  # Required for link scanning and spam heuristics
intents.voice_states = True     # Required for voice channel monitoring and mic gating
intents.moderation = True       # Required for audit logs (bans, kicks, timeouts)

class SecurityBot(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None
        )
        self.health_app: web.Application = web.Application()
        self.health_runner: web.AppRunner = None

    async def _health_handler(self, request: web.Request) -> web.Response:
        """Endpoint for Docker container health check probes."""
        is_ready = self.is_ready()
        status_code = 200 if is_ready else 503
        data = {
            "status": "healthy" if is_ready else "starting",
            "latency_ms": round(self.latency * 1000) if is_ready else None,
            "guilds": len(self.guilds) if is_ready else 0,
            "dry_run": bot_config.dry_run
        }
        return web.json_response(data, status=status_code)

    async def _start_healthcheck_server(self):
        """Starts the aiohttp server on HEALTH_PORT for container probes & web dashboard."""
        self.health_app.router.add_get("/health", self._health_handler)
        setup_dashboard_routes(self.health_app, self)
        self.health_runner = web.AppRunner(self.health_app)
        await self.health_runner.setup()
        site = web.TCPSite(self.health_runner, "0.0.0.0", bot_config.health_port)
        await site.start()
        logger.info("Web dashboard & health server listening on port %d", bot_config.health_port)

    async def setup_hook(self):
        """Executes initialization steps before gateway login."""
        # 1. Initialize SQLite Database
        await db.init_db()

        # 2. Load dynamic bypasses from database
        bypasses = await db.get_all_bypasses()
        for b in bypasses:
            if b["bypass_type"] == "role":
                bot_config.dynamic_bypass_roles.add(b["target_id"])
            elif b["bypass_type"] == "user":
                bot_config.dynamic_bypass_users.add(b["target_id"])
            elif b["bypass_type"] == "channel":
                bot_config.dynamic_bypass_channels.add(b["target_id"])
        logger.info("Loaded %d dynamic owner bypasses from database", len(bypasses))

        # 3. Load per-guild settings into cache
        try:
            import aiosqlite
            async with aiosqlite.connect(db.db_path) as conn:
                conn.row_factory = aiosqlite.Row
                async with conn.execute("SELECT * FROM guild_settings") as cursor:
                    rows = await cursor.fetchall()
                    for r in rows:
                        bot_config.guild_settings_cache[r["guild_id"]] = dict(r)
            logger.info("Loaded settings for %d guilds from database", len(bot_config.guild_settings_cache))
        except Exception as e:
            logger.error("Failed loading guild settings: %s", e)

        # 3. Load Security Cogs
        extensions = [
            "src.cogs.moderation_view",
            "src.cogs.trust_gate",
            "src.cogs.voice_protection",
            "src.cogs.raid_detector",
            "src.cogs.spam_detector",
            "src.cogs.link_filter",
            "src.cogs.attachment_scanner",
            "src.cogs.invite_filter",
            "src.cogs.account_anomaly",
            "src.cogs.name_sanitizer",
            "src.cogs.webhook_guard",
            "src.cogs.lockdown",
            "src.cogs.admin",
            "src.cogs.help",
            "src.cogs.logging_system"
        ]

        for ext in extensions:
            try:
                await self.load_extension(ext)
                logger.info("Loaded extension: %s", ext)
            except Exception as e:
                logger.error("Failed to load extension %s: %s", ext, e)

        # 4. Start health check server
        await self._start_healthcheck_server()

        # 5. Start maintenance loop
        self.maintenance_task.start()

    @tasks.loop(hours=24)
    async def maintenance_task(self):
        """Daily privacy maintenance: prunes old incident audit logs."""
        try:
            days = bot_config.audit_retention_days
            await db.prune_old_records(retention_days=days)
        except Exception as e:
            logger.error("Error running daily audit pruning: %s", e)

    async def on_ready(self):
        logger.info("=" * 50)
        logger.info("Security Bot connected as: %s (ID: %d)", self.user, self.user.id)
        logger.info("Operational Mode: %s", "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT")
        logger.info("Monitored Guilds: %d", len(self.guilds))
        logger.info("=" * 50)

        # Sync slash commands
        try:
            if bot_config.guild_id:
                guild = discord.Object(id=bot_config.guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                logger.info("Synchronized %d slash commands to guild %d", len(synced), bot_config.guild_id)
            else:
                synced = await self.tree.sync()
                logger.info("Synchronized %d global slash commands", len(synced))
        except Exception as e:
            logger.error("Failed to sync slash commands: %s", e)

    async def close(self):
        """Graceful shutdown handler."""
        if self.health_runner:
            await self.health_runner.cleanup()
        await super().close()

def main():
    token = bot_config.discord_token
    if not token or token == "your_bot_token_here":
        logger.critical("No valid DISCORD_TOKEN found in .env. Please configure your bot token!")
        print("\n[ERROR] DISCORD_TOKEN is missing! Please configure .env before starting the bot.\n")
        sys.exit(1)

    bot = SecurityBot()
    try:
        bot.run(token, log_handler=None)
    except discord.LoginFailure:
        logger.critical("Invalid Discord token provided.")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Bot stopped by user.")

if __name__ == "__main__":
    main()

"""Core entry point for the Discord Security Bot.
Initializes Gateway connection, least-privilege intents, health check server, and security cogs.
"""
import os
import sys
import asyncio
import logging
from typing import Optional
from datetime import datetime, timezone
import aiohttp
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

# Comprehensive Gateway Intents for Full Security & Audit Logging
intents = discord.Intents.default()
intents.members = True          # Required for join raid detection and account age audits
intents.message_content = True  # Required for link scanning and spam heuristics

class SecurityBot(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None
        )
        self.http.user_agent = "DiscordBot (https://github.com/Rapptz/discord.py, 2.7.1) Python/3.11 aiohttp/3.9.5"
        self.health_app: web.Application = web.Application()
        self.health_runner: web.AppRunner = None
        self.keep_alive_task: Optional[asyncio.Task] = None

    async def _health_handler(self, request: web.Request) -> web.Response:
        """Endpoint for Render container health check probes & keep-alive monitors."""
        is_ready = self.is_ready()
        data = {
            "status": "healthy" if is_ready else "starting",
            "bot": "Karuppu Security Bot",
            "latency_ms": round(self.latency * 1000) if is_ready and self.latency is not None else None,
            "guilds": len(self.guilds) if is_ready else 0,
            "dry_run": bot_config.dry_run
        }
        return web.json_response(data, status=200)

    async def _start_healthcheck_server(self):
        """Starts the aiohttp server on HEALTH_PORT for container probes & web dashboard."""
        self.health_app.router.add_get("/", self._health_handler)
        self.health_app.router.add_get("/health", self._health_handler)
        setup_dashboard_routes(self.health_app, self)
        self.health_runner = web.AppRunner(self.health_app)
        await self.health_runner.setup()
        site = web.TCPSite(self.health_runner, "0.0.0.0", bot_config.health_port)
        await site.start()
        logger.info("Web dashboard & health server listening on port %d", bot_config.health_port)

    async def _keep_alive_loop(self):
        """Continuously pings public URL every 8 minutes to prevent Render free tier from sleeping."""
        await self.wait_until_ready()
        external_url = os.getenv("RENDER_EXTERNAL_URL") or "https://karuppu-security-bot.onrender.com"
        target_url = f"{external_url.rstrip('/')}/health"
        logger.info("24/7 Keep-Alive pinger started for target: %s", target_url)

        # Wait 30 seconds before first ping
        await asyncio.sleep(30)
        while not self.is_closed():
            try:
                import aiohttp
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                    async with session.get(target_url, headers={"User-Agent": "KaruppuKeepAlive/1.0"}) as resp:
                        logger.info("24/7 Keep-Alive ping to %s returned HTTP %d", target_url, resp.status)
            except Exception as e:
                logger.debug("Keep-Alive ping notice: %s", e)

            # Wait 8 minutes (480s) before next ping (Render sleep threshold is 15 minutes)
            await asyncio.sleep(480)

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

        # 3b. Load Dedicated Granular Log Channels (24-Channel Suite)
        try:
            log_entries = await db.get_all_guild_log_channels()
            for entry in log_entries:
                bot_config.guild_log_channels_cache[(entry["guild_id"], entry["log_type"])] = entry["channel_id"]
            logger.info("Loaded %d granular log channel mappings into cache", len(bot_config.guild_log_channels_cache))
        except Exception as e:
            logger.error("Failed loading granular log channel mappings: %s", e)

        # 2b. Load Active Voice Channel Punishments (VC Bans and Timeouts)
        try:
            active_punishments = await db.get_active_vc_punishments()
            now_utc = datetime.now(timezone.utc)
            for p in active_punishments:
                exp = p.get("expires_at")
                if exp:
                    try:
                        if now_utc >= datetime.fromisoformat(exp):
                            continue
                    except Exception:
                        pass
                bot_config.vc_punishments_cache[(p["guild_id"], p["user_id"])] = p
            logger.info("Loaded %d active VC punishments into cache", len(bot_config.vc_punishments_cache))
        except Exception as e:
            logger.error("Failed loading active VC punishments: %s", e)

        # 3. Load Security Cogs
        extensions = [
            "src.cogs.trust_gate",
            "src.cogs.voice_protection",
            "src.cogs.raid_detector",
            "src.cogs.spam_detector",
            "src.cogs.anti_nuke",
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

        # 4. Start health check server if not already running
        if self.health_runner is None:
            await self._start_healthcheck_server()

        # 5. Start 24/7 Keep-Alive self-pinger task
        if self.keep_alive_task is None or self.keep_alive_task.done():
            self.keep_alive_task = asyncio.create_task(self._keep_alive_loop())

        # 6. Global Slash Command Error Handler
        async def on_tree_error(interaction: discord.Interaction, error: discord.app_commands.AppCommandError):
            logger.error("Slash command error in '%s': %s", interaction.command.name if interaction.command else "Unknown", error, exc_info=error)
            try:
                err_text = f"❌ Command error: `{error}`"
                if interaction.response.is_done():
                    await interaction.followup.send(err_text, ephemeral=True)
                else:
                    await interaction.response.send_message(err_text, ephemeral=True)
            except Exception as notify_err:
                logger.error("Failed to notify user of command error: %s", notify_err)

        self.tree.on_error = on_tree_error

        # 7. Start maintenance loop and VC punishment expiry monitor
        self.maintenance_task.start()
        self.vc_punishment_expiry_task.start()

    @tasks.loop(seconds=30)
    async def vc_punishment_expiry_task(self):
        """Monitors and automatically lifts expired voice channel timeouts."""
        now_utc = datetime.now(timezone.utc)
        expired_keys = []
        for key, punishment in list(bot_config.vc_punishments_cache.items()):
            exp_str = punishment.get("expires_at")
            if not exp_str:
                continue
            try:
                exp_dt = datetime.fromisoformat(exp_str)
                if now_utc >= exp_dt:
                    expired_keys.append((key, punishment))
            except Exception:
                pass

        for (guild_id, user_id), punishment in expired_keys:
            bot_config.vc_punishments_cache.pop((guild_id, user_id), None)
            await db.remove_vc_punishment(guild_id, user_id, punishment.get("punishment_type"))
            guild = self.get_guild(guild_id)
            if guild:
                member = guild.get_member(user_id)
                if member and member.voice and member.voice.mute:
                    try:
                        await member.edit(mute=False, reason="VC Timeout auto-expired")
                    except Exception:
                        pass
                if guild.me.guild_permissions.manage_channels and member:
                    for vc in guild.voice_channels + guild.stage_channels:
                        try:
                            await vc.set_permissions(member, overwrite=None, reason="VC Timeout auto-expired")
                        except Exception:
                            pass
                log_ch_id = bot_config.get_log_channel_id(guild_id, "mod") or bot_config.get_log_channel_id(guild_id, "voice")
                if log_ch_id:
                    ch = guild.get_channel(log_ch_id)
                    if isinstance(ch, discord.TextChannel):
                        embed = discord.Embed(
                            title="🔊 Voice Channel Timeout Expired",
                            color=discord.Color.green(),
                            description=f"<@{user_id}>'s voice timeout has expired. Voice channel access restored.",
                            timestamp=now_utc
                        )
                        try:
                            await ch.send(embed=embed)
                        except Exception:
                            pass

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

        # Slash commands: avoid spamming global tree.sync() on every restart to prevent Cloudflare 429 IP bans.
        # Use '!sync' in chat to refresh commands on-demand.
        logger.info("Bot connected to Gateway. Slash commands are registered globally (use '!sync' to force refresh).")

        # 3. Auto-discover and bind existing log channels for all guilds
        from src.cogs.admin import FULL_LOG_CHANNELS
        for guild in self.guilds:
            try:
                discovered = 0
                for cat in guild.categories:
                    cat_lower = cat.name.lower()
                    if "log" in cat_lower or "𝚲" in cat.name or "security" in cat_lower:
                        for ch in cat.text_channels:
                            cname = ch.name.lower()
                            for ch_key, _ in FULL_LOG_CHANNELS:
                                formatted_key = ch_key.replace("_", "-")
                                if (formatted_key in cname or ch_key in cname) and (guild.id, ch_key) not in bot_config.guild_log_channels_cache:
                                    bot_config.guild_log_channels_cache[(guild.id, ch_key)] = ch.id
                                    discovered += 1
                if discovered > 0:
                    logger.info("Auto-discovered %d existing log channels in guild '%s' (%d)", discovered, guild.name, guild.id)
            except Exception as disc_err:
                logger.debug("Error during auto-discovery for %s: %s", guild.name, disc_err)

        # 4. Auto-reconnect 24/7 Voice Guard to designated channels
        for guild in self.guilds:
            settings = bot_config.guild_settings_cache.get(guild.id, {})
            guard_ch_id = settings.get("guard_voice_channel_id")
            if guard_ch_id:
                ch = guild.get_channel(guard_ch_id)
                if isinstance(ch, discord.VoiceChannel):
                    try:
                        await ch.connect(self_deaf=True)
                        logger.info("Voice Guard auto-reconnected to #%s in '%s'", ch.name, guild.name)
                    except Exception as ve:
                        logger.warning("Could not auto-connect Voice Guard to #%s: %s", ch.name, ve)

    async def on_message(self, message: discord.Message):
        """Processes message commands like !sync, then forwards to cogs."""
        if message.author.bot:
            return

        cmd_trigger = message.content.strip().lower()
        # Clean duplicates / sync command for owners and admins
        if cmd_trigger in ("!sync", "!cleardupes", "!clean"):
            if not message.guild:
                return
            member = message.author
            is_admin = (
                member.id == message.guild.owner_id or
                (isinstance(member, discord.Member) and member.guild_permissions.administrator)
            )
            if not is_admin:
                await message.channel.send("❌ Only the **Server Owner** or members with **Administrator** permission can run this command.")
                return

            status_msg = await message.channel.send("🔄 **Syncing slash commands to this server...**")
            try:
                # 1. Copy global commands to this guild and sync so they become available INSTANTLY
                self.tree.copy_global_to(guild=message.guild)
                synced_guild = await self.tree.sync(guild=message.guild)

                # 2. Also ensure global commands are synced
                synced = await self.tree.sync()
                await status_msg.edit(
                    content=(
                        f"✅ **Synced {len(synced_guild)} slash commands instantly to this server!**\n"
                        f"Global registry has **{len(synced)}** commands registered.\n\n"
                        f"👉 You can use `/logs` or `/setup` right away!\n"
                        f"*(Or type `!logs` or `!setup` in chat directly anytime!)*"
                    )
                )
            except Exception as e:
                await status_msg.edit(content=f"❌ Failed to sync commands: `{e}`")
            return

        # Process any other standard prefix commands
        await self.process_commands(message)

    async def close(self):
        """Graceful shutdown handler."""
        if self.keep_alive_task and not self.keep_alive_task.done():
            self.keep_alive_task.cancel()
        if self.health_runner:
            await self.health_runner.cleanup()
            self.health_runner = None
        await super().close()

async def run_bot():
    token = bot_config.discord_token
    if not token or token == "your_bot_token_here":
        logger.critical("No valid DISCORD_TOKEN found in environment. Please configure your bot token!")
        print("\n[ERROR] DISCORD_TOKEN is missing! Please configure DISCORD_TOKEN before starting the bot.\n")
        sys.exit(1)

    bot = SecurityBot()
    # 1. Immediately start the health check web server so Render's probe passes right away
    await bot._start_healthcheck_server()

    # 2. Resilient Gateway connection loop
    backoff = 20
    while not bot.is_closed():
        try:
            logger.info("Connecting to Discord Gateway...")
            await bot.start(token)
            break
        except discord.LoginFailure as lf:
            logger.critical("Fatal: Invalid Discord token provided: %s", lf)
            sys.exit(1)
        except (discord.HTTPException, aiohttp.ClientError) as e:
            logger.warning("Discord API connection notice (%s). Waiting %ds before reconnecting...", e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 180)
        except Exception as e:
            logger.error("Unexpected error in Discord bot lifecycle: %s. Retrying in %ds...", e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 180)

def main():
    try:
        asyncio.run(run_bot())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user.")

if __name__ == "__main__":
    main()

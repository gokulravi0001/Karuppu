"""Web dashboard view handlers and API endpoints for Karuppu / Antigravity Security Suite."""
import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import jinja2
from aiohttp import web
import discord
from discord.ext import commands

from src.config import bot_config
from src.database import db
from src.dashboard.auth import auth_manager

logger = logging.getLogger("security_bot.dashboard")

# Initialize Jinja2 environment pointing to templates directory
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape=jinja2.select_autoescape(["html", "xml"])
)

class DashboardController:
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _get_session(self, request: web.Request) -> Optional[dict]:
        """Extracts and validates user session from signed cookie."""
        cookie = request.cookies.get("session")
        if not cookie:
            return None
        return auth_manager.decode_session(cookie)

    def render_page(self, template_name: str, session: Optional[dict] = None, **context) -> web.Response:
        """Renders an inner page template and injects it into base.html with global layout state."""
        user = session.get("user") if session else None
        context["user"] = user
        context["client_id"] = auth_manager.client_id

        # Render child content template
        child_template = jinja_env.get_template(template_name)
        inner_html = child_template.render(**context)

        # Render outer layout with child content
        base_template = jinja_env.get_template("base.html")
        full_html = base_template.render(content=inner_html, **context)

        return web.Response(text=full_html, content_type="text/html")

    async def _verify_admin(self, request: web.Request, guild_id: int) -> Optional[tuple[dict, discord.Guild]]:
        """Verifies that the request user is logged in and is an administrator of the specified guild."""
        session = self._get_session(request)
        if not session or "user" not in session:
            return None

        guild = self.bot.get_guild(guild_id)
        if not guild:
            return None

        user_id = int(session["user"]["id"])

        # 1. Guild owner always has access
        if guild.owner_id == user_id:
            return session, guild

        # 2. Check cached guild member permissions
        member = guild.get_member(user_id)
        if member and (member.guild_permissions.administrator or member.guild_permissions.manage_guild):
            return session, guild

        # 3. Check Discord user guilds permissions from session
        user_guilds = session.get("guilds", [])
        for g in user_guilds:
            if int(g.get("id", 0)) == guild_id:
                perms = int(g.get("permissions", 0))
                # 0x8 = ADMINISTRATOR, 0x20 = MANAGE_GUILD
                if g.get("owner") or (perms & 0x8) or (perms & 0x20):
                    return session, guild

        return None

    # ==========================================
    # PUBLIC PAGES & AUTH
    # ==========================================

    async def handle_index(self, request: web.Request) -> web.Response:
        """Landing page displaying live stats and feature highlights."""
        session = self._get_session(request)
        guild_count = len(self.bot.guilds)
        member_count = sum(g.member_count for g in self.bot.guilds if g.member_count)
        latency = round(self.bot.latency * 1000) if self.bot.latency else 0

        return self.render_page(
            "index.html",
            session=session,
            title="Antigravity Security Suite • Home",
            guild_count=guild_count,
            member_count=member_count,
            latency=latency
        )

    async def handle_terms(self, request: web.Request) -> web.Response:
        """Terms of Service page."""
        session = self._get_session(request)
        return self.render_page("terms.html", session=session, title="Terms of Service • Antigravity")

    async def handle_privacy(self, request: web.Request) -> web.Response:
        """Privacy Policy page."""
        session = self._get_session(request)
        return self.render_page("privacy.html", session=session, title="Privacy Policy • Antigravity")

    async def handle_login(self, request: web.Request) -> web.Response:
        """Redirects to Discord OAuth2 login dialog."""
        session = self._get_session(request)
        if session and "user" in session:
            raise web.HTTPFound("/dashboard")
        raise web.HTTPFound(auth_manager.get_oauth_url())

    async def handle_callback(self, request: web.Request) -> web.Response:
        """Handles Discord OAuth2 callback, exchanges code, and creates signed cookie."""
        code = request.query.get("code")
        if not code:
            raise web.HTTPFound("/")

        token_data = await auth_manager.exchange_code(code)
        if not token_data or "access_token" not in token_data:
            return web.Response(text="Authentication failed with Discord. Please try again.", status=400)

        access_token = token_data["access_token"]
        user_info = await auth_manager.fetch_user_info(access_token)
        if not user_info:
            return web.Response(text="Failed to fetch user profile from Discord.", status=400)

        # Preload guilds list
        user_guilds = await auth_manager.fetch_user_guilds(access_token)

        session_data = {
            "user": user_info,
            "access_token": access_token,
            "guilds": user_guilds,
            "created_at": datetime.now(timezone.utc).timestamp()
        }

        signed_cookie = auth_manager.sign_session(session_data)
        response = web.HTTPFound("/dashboard")
        response.set_cookie(
            "session",
            signed_cookie,
            max_age=604800,  # 7 days
            httponly=True,
            samesite="Lax"
        )
        raise response

    async def handle_logout(self, request: web.Request) -> web.Response:
        """Logs out user and clears session cookie."""
        response = web.HTTPFound("/")
        response.del_cookie("session")
        raise response

    # ==========================================
    # DASHBOARD PAGES
    # ==========================================

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """Server selector listing all manageable servers where user is Admin/Owner."""
        session = self._get_session(request)
        if not session or "user" not in session:
            raise web.HTTPFound("/auth/login")

        # Refresh or use cached guilds
        guilds_raw = session.get("guilds")
        if not guilds_raw and "access_token" in session:
            guilds_raw = await auth_manager.fetch_user_guilds(session["access_token"])
            session["guilds"] = guilds_raw

        manageable_guilds = []
        for g in (guilds_raw or []):
            perms = int(g.get("permissions", 0))
            is_admin = bool(g.get("owner")) or bool(perms & 0x8) or bool(perms & 0x20)
            if is_admin:
                guild_id = int(g["id"])
                bot_guild = self.bot.get_guild(guild_id)
                manageable_guilds.append({
                    "id": str(guild_id),
                    "name": g.get("name"),
                    "icon": g.get("icon"),
                    "bot_present": bot_guild is not None
                })

        return self.render_page(
            "dashboard.html",
            session=session,
            title="Server Selector • Antigravity Security",
            guilds=manageable_guilds
        )

    async def handle_guild_dashboard(self, request: web.Request) -> web.Response:
        """Individual server management dashboard."""
        guild_id_str = request.match_info.get("guild_id")
        try:
            guild_id = int(guild_id_str)
        except (ValueError, TypeError):
            raise web.HTTPFound("/dashboard")

        auth_result = await self._verify_admin(request, guild_id)
        if not auth_result:
            raise web.HTTPFound("/dashboard")

        session, guild = auth_result
        settings = await db.get_guild_settings(guild_id)
        if not settings:
            settings = {
                "guild_id": guild_id,
                "dry_run": 1 if bot_config.dry_run else 0
            }

        is_dry_run = bool(settings.get("dry_run", 1 if bot_config.dry_run else 0))

        # Roles in descending position (excluding @everyone)
        roles = [
            {"id": str(r.id), "name": r.name}
            for r in reversed(guild.roles)
            if r.id != guild.id
        ]

        # Text channels
        channels = [
            {"id": str(c.id), "name": c.name}
            for c in guild.text_channels
        ]

        # Recent incidents
        incidents = await db.get_recent_incidents(guild_id, limit=30)

        return self.render_page(
            "guild.html",
            session=session,
            title=f"{guild.name} Security Dashboard",
            guild=guild,
            settings=settings,
            is_dry_run=is_dry_run,
            roles=roles,
            channels=channels,
            incidents=incidents
        )

    # ==========================================
    # LIVE API ENDPOINTS
    # ==========================================

    async def api_toggle_dry_run(self, request: web.Request) -> web.Response:
        """Toggles dry run mode for a specific guild."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized or bot not in guild"}, status=403)

        settings = await db.get_guild_settings(guild_id)
        current = bool(settings.get("dry_run", 1 if bot_config.dry_run else 0))
        new_val = not current

        await db.set_guild_dry_run(guild_id, new_val)
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id]["dry_run"] = 1 if new_val else 0

        return web.json_response({"success": True, "dry_run": new_val})

    async def api_save_roles(self, request: web.Request) -> web.Response:
        """Saves progressive trust level gates."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        _, guild = auth
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        def get_role_info(role_id_raw):
            try:
                rid = int(role_id_raw or 0)
                if rid == 0:
                    return None, None
                r = guild.get_role(rid)
                return rid, (r.name if r else None)
            except Exception:
                return None, None

        link_id, link_name = get_role_info(body.get("links_role_id"))
        media_id, media_name = get_role_info(body.get("media_role_id"))
        mic_id, mic_name = get_role_info(body.get("mic_role_id"))
        archive_id, archive_name = get_role_info(body.get("zip_role_id"))
        invite_id, invite_name = get_role_info(body.get("invites_role_id"))

        role_data = {
            "link_role_id": link_id, "link_role_name": link_name,
            "media_role_id": media_id, "media_role_name": media_name,
            "mic_role_id": mic_id, "mic_role_name": mic_name,
            "archive_role_id": archive_id, "archive_role_name": archive_name,
            "invite_role_id": invite_id, "invite_role_name": invite_name
        }

        await db.update_all_role_gates(guild_id, role_data)

        # Update cache
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id].update(role_data)

        return web.json_response({"success": True, "message": "Level role gates successfully updated."})

    async def api_save_logs(self, request: web.Request) -> web.Response:
        """Saves dedicated log channels."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        def parse_cid(val):
            try:
                c = int(val or 0)
                return c if c > 0 else None
            except Exception:
                return None

        log_data = {
            "chat_log_channel_id": parse_cid(body.get("chat_log_channel_id")),
            "voice_log_channel_id": parse_cid(body.get("voice_log_channel_id")),
            "member_log_channel_id": parse_cid(body.get("member_log_channel_id")),
            "mod_log_channel_id": parse_cid(body.get("mod_log_channel_id")),
            "server_log_channel_id": parse_cid(body.get("server_log_channel_id"))
        }

        await db.update_all_log_channels(guild_id, log_data)

        # Update cache
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id].update(log_data)

        return web.json_response({"success": True, "message": "Log channel bindings saved."})

    async def api_auto_setup(self, request: web.Request) -> web.Response:
        """Triggers 1-click themed 'BEHIND THE SCENES' staff suite creation."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        _, guild = auth
        me = guild.me
        if not me.guild_permissions.manage_channels:
            return web.json_response({"error": "Bot lacks 'Manage Channels' permission in this server."}, status=400)

        # Overwrites: invisible to @everyone, visible to admins and bot
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False, send_messages=False, connect=False),
            me: discord.PermissionOverwrite(
                view_channel=True,
                send_messages=True,
                embed_links=True,
                attach_files=True,
                manage_messages=True
            )
        }

        for r in guild.roles:
            if r.permissions.administrator or r.permissions.moderate_members or r.permissions.manage_guild:
                overwrites[r] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

        category_name = "＝＝＝𓆩『  𝗕𝗘𝗛𝗜𝗡𝗗 𝗧𝗛𝗘 𝗦𝗖𝗘𝗡𝗘𝗦  』𓆪＝＝＝"
        channel_defs = [
            ("🚨・𝗰𝗼𝗺𝗺𝗮𝗻𝗱-𝗰𝗲𝗻𝘁𝗲𝗿", "alert", "Primary command center for security alerts & 1-click mod action cards"),
            ("💬・𝗰𝗵𝗮𝘁-𝗹𝗼𝗴𝘀", "chat", "Message edits & deletions with attachment filenames"),
            ("🔊・𝘃𝗼𝗶𝗰𝗲-𝗹𝗼𝗴𝘀", "voice", "Voice channel joins, leaves, switches & server mutes"),
            ("👥・𝗺𝗲𝗺𝗯𝗲𝗿-𝗹𝗼𝗴𝘀", "member", "Member joins with account age warnings (<24h) & leaves"),
            ("🔨・𝗺𝗼𝗱-𝗹𝗼𝗴𝘀", "mod", "Bans, kicks, timeouts, who did what to whom + reasons"),
            ("📁・𝘀𝗲𝗿𝘃𝗲𝗿-𝗹𝗼𝗴𝘀", "server", "Channel and role creations/deletions")
        ]

        try:
            category = await guild.create_category(category_name, overwrites=overwrites, reason="Web dashboard staff suite setup")
            created_channels = {}

            if guild.id not in bot_config.guild_settings_cache:
                bot_config.guild_settings_cache[guild.id] = {}

            for name, ch_type, topic in channel_defs:
                ch = await guild.create_text_channel(name, category=category, topic=topic, reason="Web dashboard staff suite setup")
                created_channels[ch_type] = ch
                if ch_type == "alert":
                    await db.set_alert_channel(guild.id, ch.id)
                    bot_config.guild_settings_cache[guild.id]["alert_channel_id"] = ch.id
                else:
                    await db.set_log_channel(guild.id, ch_type, ch.id)
                    bot_config.guild_settings_cache[guild.id][f"{ch_type}_log_channel_id"] = ch.id

            # Post Welcome embed to command center
            cmd_center = created_channels["alert"]
            welcome_embed = discord.Embed(
                title="𓆩『 𝗕𝗘𝗛𝗜𝗡𝗗 𝗧𝗛𝗘 𝗦𝗖𝗘𝗡𝗘𝗦 : 𝗖𝗢𝗠𝗠𝗔𝗡𝗗 𝗖𝗘𝗡𝗧𝗘𝗥 』𓆪",
                color=discord.Color.from_rgb(43, 45, 49),
                description=(
                    f"Welcome to the **Command Center** for **{guild.name}**!\n\n"
                    "This entire category was created and synchronized directly from the **Web Dashboard**.\n"
                    "It is locked and hidden from `@everyone`—visible strictly to server administrators and staff."
                )
            )
            await cmd_center.send(embed=welcome_embed)

            return web.json_response({
                "success": True,
                "message": "Themed 'BEHIND THE SCENES' staff category and all 6 channels created and bound!"
            })
        except Exception as e:
            logger.error("Failed web auto_setup: %s", e)
            return web.json_response({"error": str(e)}, status=500)

    async def api_trigger_lockdown(self, request: web.Request) -> web.Response:
        """Triggers emergency server lockdown via LockdownCog."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        _, guild = auth
        try:
            body = await request.json()
        except Exception:
            body = {}

        duration = min(max(int(body.get("duration", 15)), 5), 180)
        reason = str(body.get("reason", "Emergency Web Dashboard Lockdown"))

        lockdown_cog = self.bot.get_cog("ServerLockdown")
        if not lockdown_cog:
            return web.json_response({"error": "Lockdown module not loaded."}, status=500)

        success, msg = await lockdown_cog.apply_lockdown(guild, duration, reason, moderator=None)
        if success:
            return web.json_response({"success": True, "message": msg})
        else:
            return web.json_response({"error": msg}, status=400)

    async def api_trigger_unlock(self, request: web.Request) -> web.Response:
        """Lifts server lockdown via LockdownCog."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        _, guild = auth
        lockdown_cog = self.bot.get_cog("ServerLockdown")
        if not lockdown_cog:
            return web.json_response({"error": "Lockdown module not loaded."}, status=500)

        success, msg = await lockdown_cog.lift_lockdown(guild, moderator=None)
        if success:
            return web.json_response({"success": True, "message": msg})
        else:
            return web.json_response({"error": msg}, status=400)

    async def api_purge_raid(self, request: web.Request) -> web.Response:
        """Executes 1-click raid wave purge."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        _, guild = auth
        try:
            body = await request.json()
        except Exception:
            body = {}

        minutes = min(max(int(body.get("within_minutes", 15)), 1), 60)
        action_type = "ban" if str(body.get("action")).lower() == "ban" else "kick"

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        candidates = []

        for mem in guild.members:
            if mem.bot or mem.id == guild.owner_id:
                continue
            if bot_config.is_bypassed(guild, mem):
                continue
            if mem.joined_at and mem.joined_at >= cutoff:
                if len(mem.roles) <= 1:  # Only @everyone
                    candidates.append(mem)

        if not candidates:
            return web.json_response({"error": f"No candidate raid accounts found joined in the last {minutes} minutes."}, status=404)

        purged_count = 0
        for mem in candidates:
            try:
                if action_type == "ban":
                    await guild.ban(mem, reason="Web Dashboard Raid Purge", delete_message_days=1)
                else:
                    await guild.kick(mem, reason="Web Dashboard Raid Purge")
                purged_count += 1
            except Exception as e:
                logger.warning("Failed to purge candidate %s: %s", mem, e)

        # Log to audit db
        await db.log_incident(
            guild_id=guild.id,
            user_id=0,
            username="Web Dashboard Purge",
            rule_triggered="Raid Wave Purge",
            confidence="HIGH",
            raw_evidence=f"Purged {purged_count}/{len(candidates)} accounts ({action_type})",
            action_taken=f"{action_type.title()}ed {purged_count} accounts"
        )

        return web.json_response({
            "success": True,
            "message": f"Successfully {action_type}ed {purged_count} raid accounts that joined within the last {minutes} minutes."
        })

    async def api_get_incidents(self, request: web.Request) -> web.Response:
        """Returns JSON list of recent security incidents."""
        guild_id = int(request.match_info.get("guild_id"))
        auth = await self._verify_admin(request, guild_id)
        if not auth:
            return web.json_response({"error": "Unauthorized"}, status=403)

        incidents = await db.get_recent_incidents(guild_id, limit=50)
        return web.json_response({"incidents": incidents})

def setup_dashboard_routes(app: web.Application, bot: commands.Bot) -> None:
    """Registers all dashboard web and API routes to the application."""
    ctrl = DashboardController(bot)

    # Web Pages
    app.router.add_get("/", ctrl.handle_index)
    app.router.add_get("/terms", ctrl.handle_terms)
    app.router.add_get("/privacy", ctrl.handle_privacy)
    app.router.add_get("/dashboard", ctrl.handle_dashboard)
    app.router.add_get("/dashboard/guild/{guild_id}", ctrl.handle_guild_dashboard)

    # Auth
    app.router.add_get("/auth/login", ctrl.handle_login)
    app.router.add_get("/auth/callback", ctrl.handle_callback)
    app.router.add_get("/auth/logout", ctrl.handle_logout)

    # APIs
    app.router.add_post("/api/guild/{guild_id}/dry_run", ctrl.api_toggle_dry_run)
    app.router.add_post("/api/guild/{guild_id}/auto_setup", ctrl.api_auto_setup)
    app.router.add_post("/api/guild/{guild_id}/roles", ctrl.api_save_roles)
    app.router.add_post("/api/guild/{guild_id}/logs", ctrl.api_save_logs)
    app.router.add_post("/api/guild/{guild_id}/lockdown", ctrl.api_trigger_lockdown)
    app.router.add_post("/api/guild/{guild_id}/unlock", ctrl.api_trigger_unlock)
    app.router.add_post("/api/guild/{guild_id}/purge_raid", ctrl.api_purge_raid)
    app.router.add_get("/api/guild/{guild_id}/incidents", ctrl.api_get_incidents)

    logger.info("Web dashboard routes successfully registered on aiohttp web application.")

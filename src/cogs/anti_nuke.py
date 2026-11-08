"""Anti-Nuke Protection Cog.
Defends the Discord server against compromised admin accounts, rogue bots, or malicious staff:
- Mass Channel Deletions (>= 3 in 10s)
- Mass Channel Creations (>= 5 in 10s)
- Mass Role Deletions (>= 3 in 10s)
- Mass Role Creations (>= 5 in 10s)
- Mass Member Bans (>= 3 in 10s)
- Mass Member Kicks (>= 3 in 10s)
- Mass Webhook Creations (>= 3 in 10s)

Containment Action:
Strips all administrative/management roles, kicks/bans rogue bots, auto-activates lockdown,
and alerts the Server Owner immediately.
"""
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, Tuple, Optional, List
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.anti_nuke")

class AntiNukeAlertView(discord.ui.View):
    """Actions for Server Owner to review and dismiss anti-nuke incidents."""
    def __init__(self, incident_id: int, guild: discord.Guild, nuker_id: int):
        super().__init__(timeout=86400)
        self.incident_id = incident_id
        self.guild = guild
        self.nuker_id = nuker_id

    @discord.ui.button(label="Ban Offender", style=discord.ButtonStyle.danger, emoji="🔨")
    async def ban_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.guild.owner_id and not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("❌ Server Owner or Administrator permissions required.", ephemeral=True)
            return

        member = self.guild.get_member(self.nuker_id)
        if member:
            try:
                await self.guild.ban(member, reason=f"Anti-Nuke ban confirmed by {interaction.user}", delete_message_days=1)
                button.disabled = True
                button.label = "Banned"
                await interaction.message.edit(view=self)
                await interaction.response.send_message(f"🔨 Permanently banned {member.mention} (`{member.id}`).", ephemeral=True)
                return
            except Exception as e:
                await interaction.response.send_message(f"❌ Failed to ban: {e}", ephemeral=True)
                return
        await interaction.response.send_message("ℹ️ Member is no longer in the server.", ephemeral=True)

    @discord.ui.button(label="Dismiss", style=discord.ButtonStyle.secondary, emoji="🛡️")
    async def dismiss_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.guild.owner_id:
            await interaction.response.send_message("❌ Only the Server Owner can dismiss Anti-Nuke alerts.", ephemeral=True)
            return

        await db.update_incident_status(self.incident_id, "DISMISSED", interaction.user.id)
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)
        await interaction.response.send_message("✅ Anti-Nuke alert dismissed by Server Owner.", ephemeral=True)


class AntiNuke(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # (guild_id, user_id, action_type) -> deque of timestamps
        self.action_history: Dict[Tuple[int, int, str], Deque[float]] = defaultdict(deque)

    def _track_action(self, guild_id: int, user_id: int, action_type: str, threshold: int, window_secs: int) -> Tuple[bool, int]:
        now = time.time()
        key = (guild_id, user_id, action_type)
        history = self.action_history[key]
        history.append(now)

        # Prune older than window
        while history and (now - history[0]) > window_secs:
            history.popleft()

        count = len(history)
        return (count >= threshold, count)

    @commands.Cog.listener()
    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry):
        guild = entry.guild
        if not guild:
            return

        actor = entry.user
        if not actor or actor.bot and actor.id == self.bot.user.id:
            return

        # Check Proxy Bot Attribution: If action was executed by another bot, identify the human who ordered it
        real_actor = actor
        proxy_bot = None
        if actor.bot and actor.id != self.bot.user.id:
            logging_cog = self.bot.get_cog("LoggingSystem")
            if logging_cog and hasattr(logging_cog, "get_recent_bot_command_issuer"):
                human_issuer = logging_cog.get_recent_bot_command_issuer(guild.id, bot_id=actor.id, window_seconds=15.0)
                if human_issuer:
                    real_actor = human_issuer
                    proxy_bot = actor
                    logger.warning("Proxy Bot Action Detected: @%s executed action by order of human @%s (%d)", proxy_bot.name, real_actor.name, real_actor.id)

        # Server Owner is always exempt from Anti-Nuke
        if real_actor.id == guild.owner_id or (bot_config.owner_id and real_actor.id == bot_config.owner_id):
            return

        cfg = bot_config.anti_nuke
        if not cfg.get("enabled", True):
            return

        # Strict 8-second velocity window
        window_secs = int(cfg.get("window_seconds", 8))
        nuke_triggered = False
        action_name = ""
        action_count = 0

        # Rule 1: Created or Deleted 5 Channels within 8s
        if entry.action in (discord.AuditLogAction.channel_create, discord.AuditLogAction.channel_delete):
            limit = int(cfg.get("channel_mod_limit", 5))
            triggered, action_count = self._track_action(guild.id, real_actor.id, "channel_mod", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Channel Modification ({action_count} channels created/deleted within {window_secs}s)"

        # Rule 2: Created or Deleted 5 Roles within 8s
        elif entry.action in (discord.AuditLogAction.role_create, discord.AuditLogAction.role_delete):
            limit = int(cfg.get("role_mod_limit", 5))
            triggered, action_count = self._track_action(guild.id, real_actor.id, "role_mod", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Role Modification ({action_count} roles created/deleted within {window_secs}s)"

        # Rule 3: Banned or Kicked 5 or More Members within 8s
        elif entry.action in (discord.AuditLogAction.ban, discord.AuditLogAction.kick):
            limit = int(cfg.get("member_punish_limit", 5))
            triggered, action_count = self._track_action(guild.id, real_actor.id, "member_punish", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Member Punishments ({action_count} members banned/kicked within {window_secs}s)"

        # Rule 4: Mass Webhook Creations
        elif entry.action == discord.AuditLogAction.webhook_create:
            limit = int(cfg.get("webhook_create_limit", 3))
            triggered, action_count = self._track_action(guild.id, real_actor.id, "webhook_create", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Webhook Creation ({action_count} webhooks created within {window_secs}s)"

        if nuke_triggered:
            await self._contain_nuke_attack(guild, real_actor, action_name, cfg, proxy_bot=proxy_bot)

    async def _contain_nuke_attack(
        self,
        guild: discord.Guild,
        actor: discord.User | discord.Member,
        reason: str,
        cfg: dict,
        proxy_bot: Optional[discord.User | discord.Member] = None
    ):
        """Immediately neutralizes the offending account to stop further destruction:
        - Auto-quarantines the offending member (strips all roles, backs them up, applies Quarantine role, isolates channels).
        - If proxy bot was abused, neutralizes the bot's dangerous admin roles.
        - Dispatches alerts to log-antinuke, log-bot-commands, and log-security.
        """
        dry_run = bot_config.dry_run
        member = guild.get_member(actor.id) if isinstance(actor, (discord.User, discord.Member)) else None
        actions_taken = []

        if not dry_run and member:
            # 1. AUTO-QUARANTINE THE OFFENDING MEMBER
            quarantine_cog = self.bot.get_cog("quarantine")
            if quarantine_cog and isinstance(member, discord.Member):
                try:
                    q_reason = f"[Anti-Nuke Triggered] {reason}"
                    if proxy_bot:
                        q_reason += f" (via proxy bot @{proxy_bot.name})"
                    success, msg, embed = await quarantine_cog.quarantine_member(
                        guild=guild,
                        target=member,
                        moderator=guild.me,
                        reason=q_reason
                    )
                    if success:
                        actions_taken.append(f"Auto-Quarantined Member {member.mention} (Roles Backed Up & Completely Isolated)")
                        logger.warning("Auto-quarantined member %s for anti-nuke violation: %s", member, reason)
                except Exception as q_err:
                    logger.error("Failed to auto-quarantine member %s: %s", member, q_err)

            # Fallback if quarantine was not applied: strip dangerous perms or ban
            if not actions_taken:
                if member.bot:
                    try:
                        await guild.ban(member, reason=f"[Anti-Nuke Triggered] {reason}", delete_message_days=1)
                        actions_taken.append(f"Permanently Banned Rogue Bot {member.mention}")
                    except Exception as e:
                        logger.error("Failed to ban rogue bot %s: %s", member, e)
                else:
                    dangerous_perms = ("administrator", "manage_guild", "manage_channels", "manage_roles", "ban_members", "kick_members")
                    stripped = []
                    for r in member.roles:
                        if r.id == guild.id:
                            continue
                        if any(getattr(r.permissions, p, False) for p in dangerous_perms):
                            try:
                                await member.remove_roles(r, reason=f"[Anti-Nuke Triggered] {reason}")
                                stripped.append(r.name)
                            except Exception:
                                pass
                    if stripped:
                        actions_taken.append(f"Stripped Admin Roles ({', '.join(stripped)})")

            # 2. If a Proxy Bot was used by the member, neutralize the bot
            if proxy_bot and not dry_run:
                proxy_member = guild.get_member(proxy_bot.id)
                if proxy_member:
                    dangerous_perms = ("administrator", "manage_guild", "manage_channels", "manage_roles", "ban_members", "kick_members")
                    bot_stripped = []
                    for r in proxy_member.roles:
                        if r.id == guild.id:
                            continue
                        if any(getattr(r.permissions, p, False) for p in dangerous_perms):
                            try:
                                await proxy_member.remove_roles(r, reason=f"Proxy Bot Abuse containment by {actor}")
                                bot_stripped.append(r.name)
                            except Exception:
                                pass
                    if bot_stripped:
                        actions_taken.append(f"Neutralized Proxy Bot {proxy_bot.mention} (Removed: {', '.join(bot_stripped)})")

            # 3. Auto-Lockdown public channels if configured
            if cfg.get("auto_lockdown", True):
                lockdown_cog = self.bot.get_cog("ServerLockdown")
                if lockdown_cog:
                    await lockdown_cog.apply_lockdown(guild, duration_minutes=30, reason=f"Anti-Nuke Containment: {reason}")
                    actions_taken.append("Activated 30m Public Server Lockdown")

        action_summary = "; ".join(actions_taken) if actions_taken else ("[DRY RUN] Would Auto-Quarantine & Lockdown" if dry_run else "Containment Attempted")

        # Log incident in audit database
        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=actor.id,
            username=str(actor),
            rule_triggered=f"Anti-Nuke: {reason}",
            confidence="CRITICAL (100% Deterministic Audit Event)",
            raw_evidence=f"{reason} | Proxy Bot: {proxy_bot.name if proxy_bot else 'None'}",
            action_taken=action_summary
        )

        # Dispatch Emergency Alert to Alert Channel & Dedicated Log Channels
        embed = discord.Embed(
            title="🚨🚨 CRITICAL ANTI-NUKE ATTACK NEUTRALIZED",
            color=discord.Color.dark_red(),
            description=(
                f"**A severe nuke attack was detected on {guild.name}!**\n\n"
                f"• **Perpetrator (Human):** {actor.mention} (`{actor.name}` - ID: `{actor.id}`)\n"
                + (f"• **Proxy Bot Utilized:** {proxy_bot.mention} (`{proxy_bot.name}` - ID: `{proxy_bot.id}`)\n" if proxy_bot else "")
                + f"• **Attack Vector:** `{reason}`\n"
                f"• **Containment Action:** **{action_summary}**\n\n"
                f"🔒 Offender has been isolated into Quarantine and public channels secured."
            ),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text=f"Incident #{incident_id} • Karuppu Anti-Nuke Engine")

        view = AntiNukeAlertView(incident_id=incident_id, guild=guild, nuker_id=actor.id)
        
        # Dispatch to antinuke, bot_commands, and security channels
        target_channel_keys = ("antinuke", "bot_commands", "security")
        for key in target_channel_keys:
            ch_id = bot_config.get_log_channel_id(guild.id, key)
            if ch_id:
                ch = self.bot.get_channel(ch_id)
                if isinstance(ch, discord.TextChannel):
                    try:
                        await ch.send(content="@everyone ⚠️ **SERVER NUKE DETECTED & NEUTRALIZED!**" if key == "antinuke" else None, embed=embed, view=view if key == "antinuke" else None)
                    except Exception:
                        pass

        # Send DM to Server Owner
        try:
            owner = guild.owner
            if owner and not owner.bot:
                await owner.send(
                    f"⚠️ **URGENT SECURITY ALERT for {guild.name}**\n"
                    f"Anti-Nuke triggered against **{actor}** (`{actor.id}`).\n"
                    f"**Vector:** {reason}\n"
                    f"**Action Taken:** {action_summary}\n"
                    f"Please review your server audit logs immediately."
                )
        except Exception:
            pass

async def setup(bot: commands.Bot):
    await bot.add_cog(AntiNuke(bot))

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

        # Server Owner is always exempt from Anti-Nuke
        if actor.id == guild.owner_id or (bot_config.owner_id and actor.id == bot_config.owner_id):
            return

        cfg = bot_config.anti_nuke
        if not cfg.get("enabled", True):
            return

        window_secs = int(cfg.get("window_seconds", 10))
        nuke_triggered = False
        action_name = ""
        action_count = 0

        # 1. Channel Deletions
        if entry.action == discord.AuditLogAction.channel_delete:
            limit = int(cfg.get("channel_delete_limit", 3))
            triggered, action_count = self._track_action(guild.id, actor.id, "channel_delete", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Channel Deletion ({action_count} channels deleted in {window_secs}s)"

        # 2. Channel Creations (Spam Channels)
        elif entry.action == discord.AuditLogAction.channel_create:
            limit = int(cfg.get("channel_create_limit", 5))
            triggered, action_count = self._track_action(guild.id, actor.id, "channel_create", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Channel Creation ({action_count} channels created in {window_secs}s)"

        # 3. Role Deletions
        elif entry.action == discord.AuditLogAction.role_delete:
            limit = int(cfg.get("role_delete_limit", 3))
            triggered, action_count = self._track_action(guild.id, actor.id, "role_delete", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Role Deletion ({action_count} roles deleted in {window_secs}s)"

        # 4. Role Creations
        elif entry.action == discord.AuditLogAction.role_create:
            limit = int(cfg.get("role_create_limit", 5))
            triggered, action_count = self._track_action(guild.id, actor.id, "role_create", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Role Creation ({action_count} roles created in {window_secs}s)"

        # 5. Mass Bans
        elif entry.action == discord.AuditLogAction.ban:
            limit = int(cfg.get("mass_ban_limit", 3))
            triggered, action_count = self._track_action(guild.id, actor.id, "mass_ban", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Member Ban ({action_count} accounts banned in {window_secs}s)"

        # 6. Mass Kicks
        elif entry.action == discord.AuditLogAction.kick:
            limit = int(cfg.get("mass_kick_limit", 3))
            triggered, action_count = self._track_action(guild.id, actor.id, "mass_kick", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Member Kick ({action_count} accounts kicked in {window_secs}s)"

        # 7. Webhook Creations
        elif entry.action == discord.AuditLogAction.webhook_create:
            limit = int(cfg.get("webhook_create_limit", 3))
            triggered, action_count = self._track_action(guild.id, actor.id, "webhook_create", limit, window_secs)
            if triggered:
                nuke_triggered = True
                action_name = f"Mass Webhook Creation ({action_count} webhooks created in {window_secs}s)"

        if nuke_triggered:
            await self._contain_nuke_attack(guild, actor, action_name, cfg)

    async def _contain_nuke_attack(
        self,
        guild: discord.Guild,
        actor: discord.User | discord.Member,
        reason: str,
        cfg: dict
    ):
        """Immediately neutralizes the offending account to stop further destruction."""
        dry_run = bot_config.dry_run
        member = guild.get_member(actor.id)
        action_mode = str(cfg.get("action", "strip_roles")).lower()
        actions_taken = []

        if not dry_run and member:
            # 1. If rogue bot or action is ban: Ban immediately
            if member.bot or action_mode == "ban":
                try:
                    await guild.ban(member, reason=f"[Anti-Nuke Triggered] {reason}", delete_message_days=1)
                    actions_taken.append(f"Permanently Banned Rogue {'Bot' if member.bot else 'Account'}")
                except Exception as e:
                    logger.error("Failed to ban nuker %s: %s", member, e)

            # 2. Otherwise strip all dangerous admin/management roles
            if not actions_taken:
                dangerous_perms = ("administrator", "manage_guild", "manage_channels", "manage_roles", "ban_members", "kick_members")
                stripped_roles = []
                for r in member.roles:
                    if r.id == guild.id:  # @everyone
                        continue
                    perms = r.permissions
                    if any(getattr(perms, p, False) for p in dangerous_perms):
                        try:
                            await member.remove_roles(r, reason=f"[Anti-Nuke Triggered] {reason}")
                            stripped_roles.append(r.name)
                        except Exception:
                            pass
                if stripped_roles:
                    actions_taken.append(f"Stripped {len(stripped_roles)} Admin/Mod Roles ({', '.join(stripped_roles)})")
                else:
                    try:
                        await member.timeout(timedelta(days=7), reason=f"[Anti-Nuke Triggered] {reason}")
                        actions_taken.append("Applied 7-Day Containment Timeout")
                    except Exception:
                        pass

            # 3. Auto-Lockdown public channels if configured
            if cfg.get("auto_lockdown", True):
                lockdown_cog = self.bot.get_cog("ServerLockdown")
                if lockdown_cog:
                    await lockdown_cog.apply_lockdown(guild, duration_minutes=30, reason=f"Anti-Nuke Containment: {reason}")
                    actions_taken.append("Activated 30m Public Server Lockdown")

        action_summary = "; ".join(actions_taken) if actions_taken else ("[DRY RUN] Would Strip Roles & Lockdown" if dry_run else "Containment Attempted")

        # Log incident in audit database
        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=actor.id,
            username=str(actor),
            rule_triggered=f"Anti-Nuke: {reason}",
            confidence="CRITICAL (100% Deterministic Audit Event)",
            raw_evidence=reason,
            action_taken=action_summary
        )

        # Dispatch Emergency Alert to Alert Channel
        alert_ch_id = bot_config.alert_channel_id
        alert_channel = self.bot.get_channel(alert_ch_id) if alert_ch_id else None

        embed = discord.Embed(
            title="🚨🚨 CRITICAL ANTI-NUKE ATTACK NEUTRALIZED",
            color=discord.Color.dark_red(),
            description=(
                f"**A severe nuke attack was detected on {guild.name}!**\n\n"
                f"• **Offender:** {actor.mention} (`{actor.name}` - ID: `{actor.id}`)\n"
                f"• **Attack Vector:** `{reason}`\n"
                f"• **Offender Type:** `{'🤖 Discord Bot' if actor.bot else '👤 User Account'}`\n"
                f"• **Containment Action:** **{action_summary}**\n\n"
                f"🔒 Public channels have been locked down to safeguard server integrity."
            ),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text=f"Incident #{incident_id} • Antigravity Anti-Nuke Engine")

        view = AntiNukeAlertView(incident_id=incident_id, guild=guild, nuker_id=actor.id)
        if alert_channel:
            await alert_channel.send(content="@everyone ⚠️ **SERVER NUKE DETECTED!**", embed=embed, view=view)

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

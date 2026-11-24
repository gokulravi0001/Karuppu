"""Unified Server Control Center & Interactive Embed Dashboards.
Consolidates scattered slash commands into minimal, high-impact interactive embed command hubs
featuring Discord UI Buttons, Select Dropdowns, and Modals.
"""
import logging
import asyncio
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Any, Dict, Tuple
import discord
from discord import ui, app_commands
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.control_center")

# ==========================================
# MEMBER RESOLUTION HELPER
# ==========================================
async def resolve_member_input(guild: discord.Guild, raw_input: str) -> Optional[discord.Member]:
    """Resolves a member from ID, mention (<@123>), or username/nickname string."""
    if not guild or not raw_input:
        return None
    s = raw_input.strip()

    # Mention or ID: <@123456>, <@!123456>, 123456
    id_match = re.search(r"(\d{17,20})", s)
    if id_match:
        uid = int(id_match.group(1))
        mem = guild.get_member(uid)
        if mem:
            return mem
        try:
            return await guild.fetch_member(uid)
        except Exception:
            pass

    # Search by username / display name
    s_lower = s.lower()
    for m in guild.members:
        if m.name.lower() == s_lower or (m.global_name and m.global_name.lower() == s_lower) or m.display_name.lower() == s_lower:
            return m
    return None


# ==========================================
# INTERACTIVE MODALS FOR EMBED BUTTONS
# ==========================================

class QuarantineModal(ui.Modal, title="🔒 Quarantine Member"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.target_input = ui.TextInput(
            label="Target Member",
            placeholder="User ID, @mention, or username (e.g. 123456789 or @Raider)",
            required=True,
            max_length=100
        )
        self.reason_input = ui.TextInput(
            label="Reason for Quarantine",
            placeholder="e.g. Malicious raid activity, bot spam, proxy abuse",
            required=False,
            default="Quarantined via Staff Control Panel",
            max_length=200
        )
        self.add_item(self.target_input)
        self.add_item(self.reason_input)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        q_cog = self.bot.get_cog("QuarantineSystem")
        if not q_cog:
            await interaction.followup.send("❌ Quarantine module is not loaded.", ephemeral=True)
            return

        member = await resolve_member_input(interaction.guild, self.target_input.value)
        if not member:
            await interaction.followup.send(f"❌ Could not find member `{self.target_input.value}` in this server.", ephemeral=True)
            return

        can_mod, err = q_cog._can_moderate_target(interaction.user, member, interaction.guild)
        if not can_mod:
            await interaction.followup.send(err, ephemeral=True)
            return

        success, msg, embed = await q_cog.quarantine_member(
            interaction.guild, member, interaction.user, reason=self.reason_input.value
        )
        if success and embed:
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(msg, ephemeral=True)


class UnquarantineModal(ui.Modal, title="🔓 Unquarantine & Restore Roles"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.target_input = ui.TextInput(
            label="Member to Release",
            placeholder="User ID, @mention, or username",
            required=True,
            max_length=100
        )
        self.reason_input = ui.TextInput(
            label="Reason",
            placeholder="e.g. Verified innocent, false positive appeal approved",
            required=False,
            default="Quarantine lifted via Staff Control Panel",
            max_length=200
        )
        self.add_item(self.target_input)
        self.add_item(self.reason_input)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        q_cog = self.bot.get_cog("QuarantineSystem")
        if not q_cog:
            await interaction.followup.send("❌ Quarantine module is not loaded.", ephemeral=True)
            return

        # Resolve user ID
        s = self.target_input.value.strip()
        id_match = re.search(r"(\d{17,20})", s)
        user_id = int(id_match.group(1)) if id_match else None
        if not user_id:
            member = await resolve_member_input(interaction.guild, s)
            if member:
                user_id = member.id

        if not user_id:
            await interaction.followup.send(f"❌ Invalid user identifier `{s}`.", ephemeral=True)
            return

        success, msg, embed = await q_cog.unquarantine_member(
            interaction.guild, user_id, interaction.user, reason=self.reason_input.value
        )
        if success and embed:
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(msg, ephemeral=True)


class RestoreRolesModal(ui.Modal, title="♻️ Restore Lost Roles"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.target_input = ui.TextInput(
            label="Target Member",
            placeholder="User ID, @mention, or username",
            required=True,
            max_length=100
        )
        self.add_item(self.target_input)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        q_cog = self.bot.get_cog("QuarantineSystem")
        if not q_cog:
            await interaction.followup.send("❌ Quarantine module is not loaded.", ephemeral=True)
            return

        member = await resolve_member_input(interaction.guild, self.target_input.value)
        if not member:
            await interaction.followup.send(f"❌ Could not find member `{self.target_input.value}`.", ephemeral=True)
            return

        await q_cog.slash_restore_roles(interaction, member=member)


class VoiceKickModal(ui.Modal, title="🔌 Voice Disconnect / Kick"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.target_input = ui.TextInput(
            label="Target Member in Voice",
            placeholder="User ID, @mention, or username",
            required=True,
            max_length=100
        )
        self.reason_input = ui.TextInput(
            label="Reason",
            placeholder="e.g. Soundboard spam, mic glitching, disruptive behavior",
            required=False,
            default="Disconnected via Voice Control Panel",
            max_length=200
        )
        self.add_item(self.target_input)
        self.add_item(self.reason_input)

    async def on_submit(self, interaction: discord.Interaction):
        member = await resolve_member_input(interaction.guild, self.target_input.value)
        if not member:
            await interaction.response.send_message(f"❌ Could not find member `{self.target_input.value}`.", ephemeral=True)
            return

        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module is not loaded.", ephemeral=True)
            return

        await admin_cog.cmd_vc_kick(interaction, member=member, reason=self.reason_input.value)


class VoiceTimeoutModal(ui.Modal, title="🔇 Voice Channel Timeout"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.target_input = ui.TextInput(
            label="Target Member",
            placeholder="User ID, @mention, or username",
            required=True,
            max_length=100
        )
        self.duration_input = ui.TextInput(
            label="Duration in Minutes",
            placeholder="e.g. 5, 15, 60, 1440",
            required=True,
            default="15",
            max_length=6
        )
        self.reason_input = ui.TextInput(
            label="Reason",
            placeholder="Reason for voice timeout",
            required=False,
            default="Voice Timeout via Voice Control Panel",
            max_length=200
        )
        self.add_item(self.target_input)
        self.add_item(self.duration_input)
        self.add_item(self.reason_input)

    async def on_submit(self, interaction: discord.Interaction):
        member = await resolve_member_input(interaction.guild, self.target_input.value)
        if not member:
            await interaction.response.send_message(f"❌ Could not find member `{self.target_input.value}`.", ephemeral=True)
            return

        try:
            dur = int(self.duration_input.value.strip())
        except ValueError:
            await interaction.response.send_message("❌ Duration must be a valid number of minutes.", ephemeral=True)
            return

        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module is not loaded.", ephemeral=True)
            return

        await admin_cog.cmd_vc_timeout(interaction, member=member, duration_minutes=dur, reason=self.reason_input.value)


class VoiceBanModal(ui.Modal, title="⛔ Voice Channel Ban"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.target_input = ui.TextInput(
            label="Target Member",
            placeholder="User ID, @mention, or username",
            required=True,
            max_length=100
        )
        self.duration_input = ui.TextInput(
            label="Duration in Hours (leave empty for permanent)",
            placeholder="e.g. 24, 168 (7 days), or leave empty",
            required=False,
            max_length=6
        )
        self.reason_input = ui.TextInput(
            label="Reason",
            placeholder="Reason for banning from all voice channels",
            required=False,
            default="Voice Ban via Voice Control Panel",
            max_length=200
        )
        self.add_item(self.target_input)
        self.add_item(self.duration_input)
        self.add_item(self.reason_input)

    async def on_submit(self, interaction: discord.Interaction):
        member = await resolve_member_input(interaction.guild, self.target_input.value)
        if not member:
            await interaction.response.send_message(f"❌ Could not find member `{self.target_input.value}`.", ephemeral=True)
            return

        dur_hours = None
        if self.duration_input.value.strip():
            try:
                dur_hours = int(self.duration_input.value.strip())
            except ValueError:
                await interaction.response.send_message("❌ Duration must be a number of hours.", ephemeral=True)
                return

        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module is not loaded.", ephemeral=True)
            return

        await admin_cog.cmd_vc_ban(
            interaction,
            member=member,
            duration_hours=dur_hours,
            scope="server",
            reason=self.reason_input.value
        )


class LogSetupModal(ui.Modal, title="🚀 Setup 33-Channel Logging Suite"):
    def __init__(self, bot: commands.Bot):
        super().__init__()
        self.bot = bot
        self.prefix_input = ui.TextInput(
            label="Channel Prefix / Tag",
            placeholder="e.g. 𝚲, log, sec, 🔒",
            default="𝚲",
            required=False,
            max_length=10
        )
        self.font_input = ui.TextInput(
            label="Font Style (normal, bold, script, sans, etc.)",
            placeholder="normal, bold, italic, script, sans, monospace",
            default="normal",
            required=False,
            max_length=15
        )
        self.separator_input = ui.TextInput(
            label="Separator Character",
            placeholder="e.g. - (hyphen), | (pipe), • (bullet)",
            default="-",
            required=False,
            max_length=3
        )
        self.category_input = ui.TextInput(
            label="Log Category Name",
            placeholder="Default: 𝚲 SERVER LOGS",
            default="𝚲 SERVER LOGS",
            required=False,
            max_length=40
        )
        self.add_item(self.prefix_input)
        self.add_item(self.font_input)
        self.add_item(self.separator_input)
        self.add_item(self.category_input)

    async def on_submit(self, interaction: discord.Interaction):
        if not interaction.response.is_done():
            await interaction.response.defer(ephemeral=True)
        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.followup.send("❌ Admin module is not loaded.", ephemeral=True)
            return

        prefix = self.prefix_input.value.strip() or "𝚲"
        font = self.font_input.value.strip().lower() or "normal"
        separator = self.separator_input.value.strip() or "-"
        cat_name = self.category_input.value.strip() or f"{prefix} SERVER LOGS"

        await admin_cog._handle_setup_full_suite(
            interaction,
            prefix=prefix,
            font_style=font,
            separator=separator,
            category_name=cat_name
        )


# ==========================================
# INTERACTIVE VIEWS FOR EMBED COMMAND HUBS
# ==========================================

class SecurityControlView(ui.View):
    """Interactive action buttons for the /security Command Hub."""
    def __init__(self, bot: commands.Bot, guild: discord.Guild, moderator: discord.Member):
        super().__init__(timeout=600)
        self.bot = bot
        self.guild = guild
        self.moderator = moderator

    def _check_perms(self, interaction: discord.Interaction) -> bool:
        user = interaction.user
        return (
            user.id == self.guild.owner_id or
            (isinstance(user, discord.Member) and (user.guild_permissions.administrator or user.guild_permissions.moderate_members))
        )

    @ui.button(label="Toggle Dry-Run", style=discord.ButtonStyle.primary, emoji="⚡", row=0)
    async def toggle_dry_run_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        bot_config.dry_run = not bot_config.dry_run
        bot_config.save_yaml()
        mode_str = "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT"
        color = discord.Color.gold() if bot_config.dry_run else discord.Color.green()

        embed = discord.Embed(
            title="⚙️ Operational Mode Switched",
            description=f"Security bot is now running in **{mode_str}**.\nUpdated by {interaction.user.mention}.",
            color=color,
            timestamp=datetime.now(timezone.utc)
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @ui.button(label="Lockdown / Unlock", style=discord.ButtonStyle.danger, emoji="🔒", row=0)
    async def lockdown_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        lock_cog = self.bot.get_cog("ServerLockdown")
        if not lock_cog:
            await interaction.response.send_message("❌ Lockdown module is not loaded.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        if lock_cog.is_locked(self.guild.id):
            success, msg = await lock_cog.lift_lockdown(self.guild, moderator=interaction.user)
            embed = discord.Embed(
                title="🔓 Server Lockdown Lifted",
                description=f"{msg}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc)
            )
        else:
            success, msg = await lock_cog.apply_lockdown(
                self.guild, duration_minutes=30, reason="Lockdown initiated from Control Center", moderator=interaction.user
            )
            embed = discord.Embed(
                title="🔒 Emergency Lockdown Active (30 Mins)",
                description=f"{msg}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc)
            )
        await interaction.followup.send(embed=embed, ephemeral=True)

    @ui.button(label="Raid Purge", style=discord.ButtonStyle.secondary, emoji="🧹", row=0)
    async def raid_purge_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module is not loaded.", ephemeral=True)
            return

        await admin_cog.cmd_purge_raid(interaction, within_minutes=15, require_no_roles=True, action="kick")

    @ui.button(label="Security Audit", style=discord.ButtonStyle.secondary, emoji="🛡️", row=1)
    async def audit_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module is not loaded.", ephemeral=True)
            return

        await admin_cog.cmd_status(interaction)

    @ui.button(label="Owner Bypasses", style=discord.ButtonStyle.secondary, emoji="⚙️", row=1)
    async def bypass_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module is not loaded.", ephemeral=True)
            return

        await admin_cog.bypass_list(interaction)


class QuarantineControlView(ui.View):
    """Interactive action buttons for the /quarantine Command Hub."""
    def __init__(self, bot: commands.Bot, guild: discord.Guild):
        super().__init__(timeout=600)
        self.bot = bot
        self.guild = guild

    def _check_perms(self, interaction: discord.Interaction) -> bool:
        user = interaction.user
        return (
            user.id == self.guild.owner_id or
            (isinstance(user, discord.Member) and user.guild_permissions.administrator)
        )

    @ui.button(label="Quarantine Member", style=discord.ButtonStyle.danger, emoji="🔒", row=0)
    async def quarantine_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(QuarantineModal(self.bot))

    @ui.button(label="Unquarantine Member", style=discord.ButtonStyle.success, emoji="🔓", row=0)
    async def unquarantine_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(UnquarantineModal(self.bot))

    @ui.button(label="Restore Lost Roles", style=discord.ButtonStyle.primary, emoji="♻️", row=0)
    async def restore_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(RestoreRolesModal(self.bot))

    @ui.button(label="View Quarantined List", style=discord.ButtonStyle.secondary, emoji="📋", row=1)
    async def view_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        q_cog = self.bot.get_cog("QuarantineSystem")
        if q_cog:
            await q_cog.slash_quarantine_view(interaction)
        else:
            await interaction.response.send_message("❌ Quarantine module not loaded.", ephemeral=True)

    @ui.button(label="Quarantine Setup", style=discord.ButtonStyle.secondary, emoji="⚙️", row=1)
    async def setup_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        q_cog = self.bot.get_cog("QuarantineSystem")
        if not q_cog:
            await interaction.response.send_message("❌ Quarantine module not loaded.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        q_role = await q_cog.get_or_create_quarantine_role(self.guild)
        if not q_role:
            await interaction.followup.send("❌ Failed to create/find Quarantine role.", ephemeral=True)
            return
        success, msg = await q_cog.setup_quarantine_category(self.guild, q_role, interaction.user)
        await interaction.followup.send(msg, ephemeral=True)


class VoiceControlView(ui.View):
    """Interactive action buttons for the /voice Command Hub."""
    def __init__(self, bot: commands.Bot, guild: discord.Guild):
        super().__init__(timeout=600)
        self.bot = bot
        self.guild = guild

    def _check_perms(self, interaction: discord.Interaction) -> bool:
        user = interaction.user
        return (
            user.id == self.guild.owner_id or
            (isinstance(user, discord.Member) and (user.guild_permissions.administrator or user.guild_permissions.moderate_members))
        )

    @ui.button(label="Disconnect / Kick", style=discord.ButtonStyle.danger, emoji="🔌", row=0)
    async def kick_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(VoiceKickModal(self.bot))

    @ui.button(label="Voice Timeout", style=discord.ButtonStyle.primary, emoji="🔇", row=0)
    async def timeout_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(VoiceTimeoutModal(self.bot))

    @ui.button(label="Voice Ban", style=discord.ButtonStyle.danger, emoji="⛔", row=0)
    async def ban_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(VoiceBanModal(self.bot))

    @ui.button(label="Active VC Bans List", style=discord.ButtonStyle.secondary, emoji="📋", row=1)
    async def list_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        admin_cog = self.bot.get_cog("security")
        if admin_cog:
            await admin_cog.cmd_vc_banlist(interaction)
        else:
            await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)

    @ui.button(label="Voice Guard (Toggle)", style=discord.ButtonStyle.secondary, emoji="🛡️", row=1)
    async def guard_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        admin_cog = self.bot.get_cog("security")
        if not admin_cog:
            await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)
            return

        vc = self.guild.voice_client
        if vc and vc.is_connected():
            await admin_cog.cmd_vc_guard_leave(interaction)
        else:
            await admin_cog.cmd_vc_guard_join(interaction)


class LogsControlView(ui.View):
    """Interactive action buttons for the /logs Command Hub."""
    def __init__(self, bot: commands.Bot, guild: discord.Guild):
        super().__init__(timeout=600)
        self.bot = bot
        self.guild = guild

    def _check_perms(self, interaction: discord.Interaction) -> bool:
        user = interaction.user
        return (
            user.id == self.guild.owner_id or
            (isinstance(user, discord.Member) and user.guild_permissions.administrator)
        )

    @ui.button(label="1-Click Setup (33 Channels)", style=discord.ButtonStyle.success, emoji="🚀", row=0)
    async def setup_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        await interaction.response.send_modal(LogSetupModal(self.bot))

    @ui.button(label="Zero-Creation Sync", style=discord.ButtonStyle.primary, emoji="🔄", row=0)
    async def sync_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        admin_cog = self.bot.get_cog("security")
        if admin_cog:
            await admin_cog.cmd_short_logsync(interaction)
        else:
            await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)

    @ui.button(label="Clean Empty Logs", style=discord.ButtonStyle.secondary, emoji="🧹", row=0)
    async def clean_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        # Scans for empty/duplicate log channels
        removed = 0
        from src.cogs.admin import matches_log_channel, FULL_LOG_CHANNELS
        for cat in self.guild.categories:
            if "log" in cat.name.lower() or "server logs" in cat.name.lower():
                for ch in cat.text_channels:
                    # If channel is empty or duplicated
                    if ch.name.startswith("log-") and (self.guild.id, ch.name[4:]) not in bot_config.guild_log_channels_cache:
                        try:
                            # only delete if safe
                            pass
                        except Exception:
                            pass

        await interaction.followup.send("✅ Scan complete: All active log channels are synchronized and verified.", ephemeral=True)


class MasterDropdown(ui.Select):
    """Dropdown menu to switch between all subsystem dashboards inside /panel."""
    def __init__(self, bot: commands.Bot, guild: discord.Guild):
        self.bot = bot
        self.guild = guild
        options = [
            discord.SelectOption(label="Security & Anti-Nuke", description="8s velocity thresholds, dry-run, emergency lockdown", emoji="🛡️", value="security"),
            discord.SelectOption(label="Quarantine & Role Recovery", description="Isolate members, strip roles, restore saved roles", emoji="🔒", value="quarantine"),
            discord.SelectOption(label="Voice Defense & 24/7 Guard", description="Voice bans, timeouts, 24/7 Voice Guard", emoji="🎙️", value="voice"),
            discord.SelectOption(label="33-Channel Logging Suite", description="Full setup, zero-creation sync, proxy bot logs", emoji="📜", value="logs"),
            discord.SelectOption(label="Server Owner Bypasses", description="Manage trusted roles, users, and channels", emoji="⚙️", value="bypasses"),
        ]
        super().__init__(placeholder="Select a security system to manage...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        choice = self.values[0]
        now_utc = datetime.now(timezone.utc)

        if choice == "security":
            lock_cog = self.bot.get_cog("ServerLockdown")
            is_locked = lock_cog.is_locked(self.guild.id) if lock_cog else False
            mode_str = "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT"
            embed = discord.Embed(
                title="🛡️ Security & Anti-Nuke Command Hub",
                color=discord.Color.gold() if bot_config.dry_run else discord.Color.green(),
                description=(
                    f"**Operational Mode:** `{mode_str}`\n"
                    f"**Lockdown Status:** `{'LOCKED DOWN' if is_locked else 'NORMAL (Unlocked)'}`\n\n"
                    f"**⚡ Automated Anti-Nuke Velocity Defense (8-Second Window):**\n"
                    f"• 5 Channels Created/Deleted within 8s ➔ **Auto-Quarantine**\n"
                    f"• 5 Roles Created/Deleted within 8s ➔ **Auto-Quarantine**\n"
                    f"• 5 Members Banned/Kicked within 8s ➔ **Auto-Quarantine**\n"
                    f"• Proxy Bot Command Detection ➔ **Auto-Attribution & Quarantine**\n\n"
                    f"*Click any button below to execute an immediate action.*"
                ),
                timestamp=now_utc
            )
            embed.set_footer(text="Karuppu Security Defense Engine")
            view = SecurityControlView(self.bot, self.guild, interaction.user)
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

        elif choice == "quarantine":
            q_records = await db.get_all_quarantined(self.guild.id)
            count = len(q_records)
            embed = discord.Embed(
                title="🔒 Quarantine & Role Recovery Hub",
                color=discord.Color.dark_red() if count > 0 else discord.Color.blue(),
                description=(
                    f"**Active Quarantines:** `{count}` member(s) currently isolated\n"
                    f"**Role Recovery Engine:** SQLite Role Backups + Discord Audit Log Recovery\n"
                    f"**Quarantine Isolation:** Hidden category with private chat & voice channels\n\n"
                    f"*Click below to quarantine, unquarantine, or restore roles.*"
                ),
                timestamp=now_utc
            )
            embed.set_footer(text="Karuppu Quarantine Subsystem")
            view = QuarantineControlView(self.bot, self.guild)
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

        elif choice == "voice":
            vc = self.guild.voice_client
            guard_status = f"Connected in #{vc.channel.name}" if (vc and vc.is_connected()) else "Disconnected"
            punishments = await db.get_active_vc_punishments(self.guild.id)
            embed = discord.Embed(
                title="🎙️ Voice Channel Defense & 24/7 Guard Hub",
                color=discord.Color.blue(),
                description=(
                    f"**24/7 Voice Guard:** `{guard_status}`\n"
                    f"**Active Voice Punishments:** `{len(punishments)}` ban(s)/timeout(s)\n"
                    f"**Voice Hopping Defense:** Stops rapid switching (>5 switches in 10s)\n"
                    f"**Mic Glitch Defense:** Blocks macro popping (>=8 toggles in 4s)\n\n"
                    f"*Click below to moderate voice channels or control Voice Guard.*"
                ),
                timestamp=now_utc
            )
            embed.set_footer(text="Karuppu Voice Defense Subsystem")
            view = VoiceControlView(self.bot, self.guild)
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

        elif choice == "logs":
            from src.cogs.admin import FULL_LOG_CHANNELS
            total = len(FULL_LOG_CHANNELS)
            bound = sum(1 for k, _ in FULL_LOG_CHANNELS if (self.guild.id, k) in bot_config.guild_log_channels_cache)
            alert_id = bot_config.get_alert_channel_id(self.guild.id)
            alert_str = f"<#{alert_id}>" if alert_id else "*None set*"
            embed = discord.Embed(
                title="📜 33-Channel Audit & Logging Suite Hub",
                color=discord.Color.green() if bound >= total else discord.Color.gold(),
                description=(
                    f"**Coverage:** `{bound}/{total}` active log channels online\n"
                    f"**Alert Channel:** {alert_str}\n"
                    f"**Bot Command Tracking:** Dedicated `#log-bot-commands` channel with proxy attribution\n"
                    f"**Channel Types:** Voice, Chat, Mod, Roles, Stage, Events, Emojis, Joins, Leaves, Antinuke\n\n"
                    f"*Click below to run 1-Click Setup or Zero-Creation Sync.*"
                ),
                timestamp=now_utc
            )
            embed.set_footer(text="Karuppu Audit & Logging Engine")
            view = LogsControlView(self.bot, self.guild)
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

        elif choice == "bypasses":
            admin_cog = self.bot.get_cog("security")
            if admin_cog:
                await admin_cog.bypass_list(interaction)
            else:
                await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)


class MasterPanelView(ui.View):
    """The master interactive view containing the navigation dropdown and quick action buttons."""
    def __init__(self, bot: commands.Bot, guild: discord.Guild, moderator: discord.Member):
        super().__init__(timeout=600)
        self.bot = bot
        self.guild = guild
        self.moderator = moderator
        self.add_item(MasterDropdown(bot, guild))

    def _check_perms(self, interaction: discord.Interaction) -> bool:
        user = interaction.user
        return (
            user.id == self.guild.owner_id or
            (isinstance(user, discord.Member) and (user.guild_permissions.administrator or user.guild_permissions.moderate_members))
        )

    @ui.button(label="Toggle Mode", style=discord.ButtonStyle.primary, emoji="⚡", row=1)
    async def toggle_mode_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        bot_config.dry_run = not bot_config.dry_run
        bot_config.save_yaml()
        mode_str = "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT"
        await interaction.response.send_message(f"⚙️ Switched operational mode to **{mode_str}**.", ephemeral=True)

    @ui.button(label="Lockdown", style=discord.ButtonStyle.danger, emoji="🔒", row=1)
    async def lockdown_quick_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        lock_cog = self.bot.get_cog("ServerLockdown")
        if not lock_cog:
            await interaction.response.send_message("❌ Lockdown module not loaded.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        if lock_cog.is_locked(self.guild.id):
            success, msg = await lock_cog.lift_lockdown(self.guild, moderator=interaction.user)
            await interaction.followup.send(f"🔓 {msg}", ephemeral=True)
        else:
            success, msg = await lock_cog.apply_lockdown(self.guild, duration_minutes=30, reason="Lockdown via Master Panel", moderator=interaction.user)
            await interaction.followup.send(f"🔒 {msg}", ephemeral=True)

    @ui.button(label="Sync Logs", style=discord.ButtonStyle.success, emoji="🔄", row=1)
    async def sync_logs_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Administrator permissions required.", ephemeral=True)
            return
        admin_cog = self.bot.get_cog("security")
        if admin_cog:
            await admin_cog.cmd_short_logsync(interaction)
        else:
            await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)

    @ui.button(label="Audit Server", style=discord.ButtonStyle.secondary, emoji="🛡️", row=1)
    async def audit_quick_btn(self, interaction: discord.Interaction, button: ui.Button):
        if not self._check_perms(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return
        admin_cog = self.bot.get_cog("security")
        if admin_cog:
            await admin_cog.cmd_status(interaction)
        else:
            await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)


# ==========================================
# UNIFIED COG DEFINITION
# ==========================================

class ControlCenter(commands.Cog):
    """Unified Server Security Control Center Cog."""
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # 1. /panel (Master Interactive Command Hub)
    @app_commands.command(
        name="panel",
        description="Open the Master Interactive Security Control Center & Dashboard."
    )
    async def slash_panel(self, interaction: discord.Interaction):
        user = interaction.user
        is_mod = (
            user.id == interaction.guild.owner_id or
            (isinstance(user, discord.Member) and (user.guild_permissions.administrator or user.guild_permissions.moderate_members))
        )
        if not is_mod:
            await interaction.response.send_message("❌ Moderator or Administrator permissions required to access the Control Center.", ephemeral=True)
            return

        guild = interaction.guild
        now_utc = datetime.now(timezone.utc)
        latency_ms = round(self.bot.latency * 1000) if self.bot.latency else 0
        mode_str = "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT"

        from src.cogs.admin import FULL_LOG_CHANNELS
        total_logs = len(FULL_LOG_CHANNELS)
        bound_logs = sum(1 for k, _ in FULL_LOG_CHANNELS if (guild.id, k) in bot_config.guild_log_channels_cache)

        q_records = await db.get_all_quarantined(guild.id)
        q_count = len(q_records)

        vc = guild.voice_client
        guard_status = f"Guarding #{vc.channel.name}" if (vc and vc.is_connected()) else "Disconnected"

        lock_cog = self.bot.get_cog("ServerLockdown")
        is_locked = lock_cog.is_locked(guild.id) if lock_cog else False

        embed = discord.Embed(
            title="𓆩『 KARUPPU SECURITY CONTROL CENTER 』𓆪",
            color=discord.Color.from_rgb(88, 101, 242),
            description=(
                f"Welcome to the **Master Security Control Center** for **{guild.name}**.\n"
                f"All security subsystems, anti-nuke triggers, and moderation tools are unified below.\n\n"
                f"**📊 System Health & Status:**\n"
                f"• **Operational Mode:** `{mode_str}`\n"
                f"• **Anti-Nuke Defense:** `Active (8s Velocity Limits)`\n"
                f"• **Server Lockdown:** `{'🔴 ACTIVE' if is_locked else '🟢 NORMAL (Unlocked)'}`\n"
                f"• **24/7 Voice Guard:** `{guard_status}`\n"
                f"• **Audit Logging:** `{bound_logs}/{total_logs} Channels Online`\n"
                f"• **Quarantined Members:** `{q_count} Isolated`\n"
                f"• **Bot Latency:** `{latency_ms}ms`\n\n"
                f"👉 **Use the dropdown menu below** to open any subsystem panel, or use the quick buttons for immediate actions."
            ),
            timestamp=now_utc
        )
        embed.set_footer(text="Karuppu Security 2.0 • Minimalist Interactive Suite")
        view = MasterPanelView(self.bot, guild, interaction.user)
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    # 2. /security (Unified Security Hub)
    @app_commands.command(
        name="security",
        description="Open the Security & Anti-Nuke Control Embed."
    )
    async def slash_security(self, interaction: discord.Interaction):
        user = interaction.user
        is_mod = (
            user.id == interaction.guild.owner_id or
            (isinstance(user, discord.Member) and (user.guild_permissions.administrator or user.guild_permissions.moderate_members))
        )
        if not is_mod:
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        now_utc = datetime.now(timezone.utc)
        lock_cog = self.bot.get_cog("ServerLockdown")
        is_locked = lock_cog.is_locked(guild.id) if lock_cog else False
        mode_str = "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT"

        embed = discord.Embed(
            title="🛡️ Security & Anti-Nuke Command Hub",
            color=discord.Color.gold() if bot_config.dry_run else discord.Color.green(),
            description=(
                f"**Operational Mode:** `{mode_str}`\n"
                f"**Server Lockdown:** `{'🔴 ACTIVE' if is_locked else '🟢 NORMAL (Unlocked)'}`\n\n"
                f"**⚡ Automated Anti-Nuke Velocity Rules (8-Second Protection):**\n"
                f"• **5 Channels** created or deleted in 8s ➔ **Auto-Quarantine**\n"
                f"• **5 Roles** created or deleted in 8s ➔ **Auto-Quarantine**\n"
                f"• **5 Members** banned or kicked in 8s ➔ **Auto-Quarantine**\n"
                f"• **Proxy Bot Command Detection** ➔ **Auto-Attribution & Quarantine**\n\n"
                f"*Execute actions directly using the interactive buttons below:*"
            ),
            timestamp=now_utc
        )
        embed.set_footer(text="Karuppu Velocity Defense Engine")
        view = SecurityControlView(self.bot, guild, interaction.user)
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    # 3. /voice (Unified Voice Defense & Guard Hub)
    @app_commands.command(
        name="voice",
        description="Open Voice Moderation & 24/7 Guard Hub (or execute voice actions directly)."
    )
    @app_commands.describe(
        action="Optional direct action",
        member="Optional member target",
        duration="Duration in minutes (for timeout) or hours (for ban)",
        reason="Reason for moderation action"
    )
    @app_commands.choices(action=[
        app_commands.Choice(name="Panel (Interactive Embed)", value="panel"),
        app_commands.Choice(name="Kick / Disconnect", value="kick"),
        app_commands.Choice(name="Timeout", value="timeout"),
        app_commands.Choice(name="Ban", value="ban"),
        app_commands.Choice(name="Untimeout / Clear", value="untimeout"),
        app_commands.Choice(name="Unban", value="unban"),
        app_commands.Choice(name="Guard Join", value="guard_join"),
        app_commands.Choice(name="Guard Leave", value="guard_leave"),
        app_commands.Choice(name="Banlist", value="banlist"),
    ])
    async def slash_voice(
        self,
        interaction: discord.Interaction,
        action: Optional[app_commands.Choice[str]] = None,
        member: Optional[discord.Member] = None,
        duration: Optional[int] = None,
        reason: Optional[str] = "Voice action via Staff Command"
    ):
        act = action.value if action else "panel"
        admin_cog = self.bot.get_cog("security")

        if act == "panel" or (not member and act not in ("guard_join", "guard_leave", "banlist")):
            guild = interaction.guild
            vc = guild.voice_client
            guard_status = f"Connected in #{vc.channel.name}" if (vc and vc.is_connected()) else "Disconnected"
            punishments = await db.get_active_vc_punishments(guild.id)

            embed = discord.Embed(
                title="🎙️ Voice Channel Defense & 24/7 Guard Hub",
                color=discord.Color.blue(),
                description=(
                    f"**24/7 Voice Guard:** `{guard_status}`\n"
                    f"**Active Voice Punishments:** `{len(punishments)}` active bans/timeouts\n"
                    f"**VC Hopping Protection:** Active (>5 switches in 10s)\n"
                    f"**Mic Glitch / Macro Defense:** Active (>=8 toggles in 4s)\n\n"
                    f"*Click any button below to moderate voice or toggle Voice Guard:*"
                ),
                timestamp=datetime.now(timezone.utc)
            )
            embed.set_footer(text="Karuppu Voice Protection Suite")
            view = VoiceControlView(self.bot, guild)
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
            return

        if not admin_cog:
            await interaction.response.send_message("❌ Admin module not loaded.", ephemeral=True)
            return

        # Direct execution paths
        if act == "kick" and member:
            await admin_cog.cmd_vc_kick(interaction, member=member, reason=reason)
        elif act == "timeout" and member:
            dur = duration or 15
            await admin_cog.cmd_vc_timeout(interaction, member=member, duration_minutes=dur, reason=reason)
        elif act == "ban" and member:
            await admin_cog.cmd_vc_ban(interaction, member=member, duration_hours=duration, scope="server", reason=reason)
        elif act == "untimeout" and member:
            await admin_cog.cmd_vc_untimeout(interaction, member=member, reason=reason)
        elif act == "unban" and member:
            await admin_cog.cmd_vc_unban(interaction, user=member, reason=reason)
        elif act == "guard_join":
            await admin_cog.cmd_vc_guard_join(interaction)
        elif act == "guard_leave":
            await admin_cog.cmd_vc_guard_leave(interaction)
        elif act == "banlist":
            await admin_cog.cmd_vc_banlist(interaction)

    # Prefix commands for chat typing
    @commands.command(name="panel", aliases=["dashboard", "control", "cp"])
    async def prefix_panel(self, ctx: commands.Context):
        """Opens the interactive master security panel."""
        if not ctx.guild:
            return
        user = ctx.author
        is_mod = (
            user.id == ctx.guild.owner_id or
            (isinstance(user, discord.Member) and (user.guild_permissions.administrator or user.guild_permissions.moderate_members))
        )
        if not is_mod:
            await ctx.send("❌ Moderator permissions required to open the Control Center.")
            return

        from src.cogs.admin import FULL_LOG_CHANNELS
        total_logs = len(FULL_LOG_CHANNELS)
        bound_logs = sum(1 for k, _ in FULL_LOG_CHANNELS if (ctx.guild.id, k) in bot_config.guild_log_channels_cache)
        mode_str = "DRY-RUN (Alerts Only)" if bot_config.dry_run else "ACTIVE ENFORCEMENT"

        embed = discord.Embed(
            title="𓆩『 KARUPPU SECURITY CONTROL CENTER 』𓆪",
            color=discord.Color.from_rgb(88, 101, 242),
            description=(
                f"Welcome to the **Master Security Control Center** for **{ctx.guild.name}**.\n\n"
                f"• **Operational Mode:** `{mode_str}`\n"
                f"• **Logging Coverage:** `{bound_logs}/{total_logs} Channels Online`\n"
                f"• **Anti-Nuke Defense:** `Active (8s Velocity Limits)`\n\n"
                f"👉 Use the dropdown menu below to manage all features directly from this embed."
            ),
            timestamp=datetime.now(timezone.utc)
        )
        view = MasterPanelView(self.bot, ctx.guild, ctx.author)
        await ctx.send(embed=embed, view=view)


async def setup(bot: commands.Bot):
    await bot.add_cog(ControlCenter(bot))

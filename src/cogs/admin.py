"""Admin & Owner Management Cog.
Handles owner-only bypass configuration, lockdown triggers, dry-run toggles, and security health audits.
"""
import asyncio
import logging
import re
import unicodedata
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple, Any, Dict, Union
import discord
from discord import app_commands
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.admin")

class RaidPurgeConfirmView(discord.ui.View):
    def __init__(self, candidates: list, action_type: str, moderator: discord.Member):
        super().__init__(timeout=60)
        self.candidates = candidates
        self.action_type = action_type
        self.moderator = moderator

    @discord.ui.button(label="Confirm Purge", style=discord.ButtonStyle.danger, emoji="⚠️")
    async def confirm_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the moderator who initiated the purge can confirm it.", ephemeral=True)
            return

        await interaction.response.defer()
        for child in self.children:
            child.disabled = True

        executed_count = 0
        guild = interaction.guild
        for mem in self.candidates:
            try:
                if self.action_type == "ban":
                    await guild.ban(mem, reason=f"Mass raid purge confirmed by {interaction.user}", delete_message_days=1)
                else:
                    await guild.kick(mem, reason=f"Mass raid purge confirmed by {interaction.user}")
                executed_count += 1
            except Exception as e:
                logger.warning("Failed to purge raid member %s: %s", mem, e)

        embed = discord.Embed(
            title=f"🧹 Raid Purge Complete: {executed_count} Accounts {self.action_type.title()}ed",
            color=discord.Color.green(),
            description=f"Successfully purged **{executed_count}** accounts that joined during the raid wave.\n**Moderator:** {interaction.user.mention}"
        )
        await interaction.message.edit(embed=embed, view=self)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="❌")
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the initiator can cancel.", ephemeral=True)
            return

        for child in self.children:
            child.disabled = True
        await interaction.message.edit(content="❌ Raid purge was cancelled. No members were affected.", embed=None, view=self)
        await interaction.response.send_message("Purge cancelled.", ephemeral=True)


# Granular 32-channel logging suite configuration:
# key: (target_channel_name, topic_description, [smart_match_aliases])
LOG_CHANNEL_CONFIG = {
    "antinuke": (
        "log-antinuke",
        "Anti-nuke: mass ban/kick, mass channel/role wipe detections",
        ["antinuke", "anti-nuke", "nuke"]
    ),
    "message": (
        "log-messages",
        "Message edits & deletions with attachment names and before/after comparisons",
        ["message", "messages", "chat", "msg"]
    ),
    "mod": (
        "log-moderation",
        "General moderation actions, warnings and staff notes",
        ["mod", "moderation", "mod-logs", "modlogs"]
    ),
    "kick": (
        "log-kicks",
        "Member kick logs: who kicked whom with reasons and roles held",
        ["kick", "kicks"]
    ),
    "ban": (
        "log-bans",
        "Server bans, unbans, voice channel bans and voice unbans",
        ["ban", "bans", "unban"]
    ),
    "timeout": (
        "log-timeouts",
        "Member timeout & untimeout logs: who timed out whom with durations and reasons",
        ["timeout", "timeouts", "mute", "mutes"]
    ),
    "voice": (
        "log-voice",
        "Voice moderation: joins, leaves, moves, server mute/unmute and server deafen/undeafen",
        ["voice", "vc", "voice-log", "voicelog"]
    ),
    "vc_state": (
        "log-vc-status",
        "Detailed member VC states: self-mute, self-deafen, webcam camera and screen share",
        ["vc_state", "vc-state", "vc-status", "vcstatus", "state"]
    ),
    "soundboard": (
        "log-soundboard",
        "Soundboard audio playback logs: audio name, sound ID and volume",
        ["soundboard", "sounds", "sound"]
    ),
    "stage": (
        "log-stage",
        "Stage channel & stage instance events: speaker requests, topics, stage open/close",
        ["stage", "stages"]
    ),
    "event": (
        "log-events",
        "Scheduled server events: creations, updates, cancellations, start & end",
        ["event", "events", "scheduled"]
    ),
    "announcement": (
        "log-announcements",
        "Announcement & news channel publishes, crossposts and channel changes",
        ["announcement", "announcements", "news"]
    ),
    "role": (
        "log-roles",
        "Role creations, deletions, edits/renames, and who gave or removed roles to/from members",
        ["role", "roles"]
    ),
    "channel": (
        "log-channels",
        "Channel creations, deletions, renames, topic edits, slowmode and permission overwrites",
        ["channel", "channels"]
    ),
    "server": (
        "log-server",
        "Server modifications: name, icon, banner, vanity URL, AFK and settings",
        ["server", "guild"]
    ),
    "member": (
        "log-members",
        "Member profile updates: nickname changes, avatars and moderation status",
        ["member", "members", "user", "users"]
    ),
    "joins": (
        "log-joins",
        "Member joins with exact account age and <24h new account security flags",
        ["join", "joins", "welcome"]
    ),
    "leaves": (
        "log-leaves",
        "Member leaves with duration spent in server and roles held",
        ["leave", "leaves"]
    ),
    "emoji": (
        "log-emojis",
        "Server emojis & stickers: creations, renames, deletions",
        ["emoji", "emojis", "sticker", "stickers"]
    ),
    "verify": (
        "log-verification",
        "Verification events & level reward role unlocks",
        ["verify", "verification"]
    ),
    "whitelist": (
        "log-whitelist",
        "Owner-authorized bypass and whitelist additions / removals",
        ["whitelist", "bypass"]
    ),
    "security": (
        "log-security",
        "Security alerts, mode toggles, quarantine actions and Voice Guard status",
        ["security", "alert", "alerts", "guard"]
    ),
    "file": (
        "log-files",
        "Scanned uploads, malicious attachments blocked and archive gates",
        ["file", "files", "attachment", "attachments"]
    ),
    "invite": (
        "log-invites",
        "Invite creations, deletions, vanity links and invite link tracking",
        ["invite", "invites"]
    ),
    "ticket": (
        "log-tickets",
        "Ticket support logs: ticket creations, closures and staff assignments",
        ["ticket", "tickets"]
    ),
    "admin": (
        "log-admin",
        "Administrative operations, security bot setup and lockdown executions",
        ["admin", "audit"]
    ),
    "boost": (
        "log-boosts",
        "Server boost events, booster milestones and server boost tier upgrades",
        ["boost", "boosts", "nitro"]
    ),
    "raid": (
        "log-raids",
        "Raid velocity tracking, raid bursts, lockdown containment & raid purges",
        ["raid", "raids", "anti-raid"]
    ),
    "misuse": (
        "log-spam",
        "Spam ceiling hits (10-message limit), rate limit violations & ping abuse",
        ["misuse", "spam"]
    ),
    "presence": (
        "log-presence",
        "Member activity, streaming broadcasts and custom status",
        ["presence", "activity", "status"]
    ),
    "automod": (
        "log-automod",
        "AutoMod detections: phishing domains, scam links, zalgo text sanitizations",
        ["automod", "auto-mod", "filters"]
    ),
    "relationship": (
        "log-integrations",
        "Server integrations, bot additions and webhook creations/deletions",
        ["relationship", "integration", "integrations", "webhook", "webhooks"]
    ),
    "bot_commands": (
        "log-bot-commands",
        "Bot command tracking, trigger attribution, slash commands & proxy abuse detection",
        ["bot_commands", "bot-commands", "botcommands", "bot-command", "bot-triggers", "bot_triggers", "commands"]
    ),
}

FULL_LOG_CHANNELS = [(k, v[1]) for k, v in LOG_CHANNEL_CONFIG.items()]


def _generate_font_maps():
    maps = {
        "bold": {},
        "italic": {},
        "bold_italic": {},
        "sans": {},
        "sans_bold": {},
        "sans_italic": {},
        "monospace": {},
        "double_struck": {},
        "smallcaps": {
            "a": "ᴀ", "b": "ʙ", "c": "ᴄ", "d": "ᴅ", "e": "ᴇ", "f": "ꜰ", "g": "ɢ", "h": "ʜ", "i": "ɪ",
            "j": "ᴊ", "k": "ᴋ", "l": "ʟ", "m": "ᴍ", "n": "ɴ", "o": "ᴏ", "p": "ᴘ", "q": "ǫ", "r": "ʀ",
            "s": "ѕ", "t": "ᴛ", "u": "ᴜ", "v": "ᴠ", "w": "ᴡ", "x": "x", "y": "ʏ", "z": "ᴢ",
            "0": "₀", "1": "₁", "2": "₂", "3": "₃", "4": "₄", "5": "₅", "6": "₆", "7": "₇", "8": "₈", "9": "₉"
        }
    }
    # Bold
    for i in range(26):
        maps["bold"][chr(ord('A') + i)] = chr(0x1D400 + i)
        maps["bold"][chr(ord('a') + i)] = chr(0x1D41A + i)
    for i in range(10):
        maps["bold"][chr(ord('0') + i)] = chr(0x1D7CE + i)

    # Italic
    for i in range(26):
        maps["italic"][chr(ord('A') + i)] = chr(0x210E if i == 7 else (0x1D434 + i))
        maps["italic"][chr(ord('a') + i)] = chr(0x1D44E + i)

    # Bold Italic
    for i in range(26):
        maps["bold_italic"][chr(ord('A') + i)] = chr(0x1D468 + i)
        maps["bold_italic"][chr(ord('a') + i)] = chr(0x1D482 + i)

    # Sans
    for i in range(26):
        maps["sans"][chr(ord('A') + i)] = chr(0x1D5A0 + i)
        maps["sans"][chr(ord('a') + i)] = chr(0x1D5BA + i)
    for i in range(10):
        maps["sans"][chr(ord('0') + i)] = chr(0x1D7E2 + i)

    # Sans Bold
    for i in range(26):
        maps["sans_bold"][chr(ord('A') + i)] = chr(0x1D5D4 + i)
        maps["sans_bold"][chr(ord('a') + i)] = chr(0x1D5EE + i)
    for i in range(10):
        maps["sans_bold"][chr(ord('0') + i)] = chr(0x1D7EC + i)

    # Sans Italic
    for i in range(26):
        maps["sans_italic"][chr(ord('A') + i)] = chr(0x1D608 + i)
        maps["sans_italic"][chr(ord('a') + i)] = chr(0x1D622 + i)

    # Monospace
    for i in range(26):
        maps["monospace"][chr(ord('A') + i)] = chr(0x1D670 + i)
        maps["monospace"][chr(ord('a') + i)] = chr(0x1D68A + i)
    for i in range(10):
        maps["monospace"][chr(ord('0') + i)] = chr(0x1D7F6 + i)

    # Double Struck
    for i in range(26):
        maps["double_struck"][chr(ord('A') + i)] = chr(0x1D538 + i)
        maps["double_struck"][chr(ord('a') + i)] = chr(0x1D552 + i)
    for i in range(10):
        maps["double_struck"][chr(ord('0') + i)] = chr(0x1D7D8 + i)

    return maps

FONT_MAPS = _generate_font_maps()
SMALLCAPS_INVERSE = {v: k for k, v in FONT_MAPS["smallcaps"].items()}


def apply_font(text: str, font_style: Optional[str]) -> str:
    """Applies a unicode font style or mirrors the font of a user-provided sample string."""
    if not font_style or font_style.strip().lower() in ["normal", "none", "standard", "default", ""]:
        return text

    style_clean = font_style.strip().lower().replace("-", "_").replace(" ", "_")
    mapping = FONT_MAPS.get(style_clean)

    if not mapping:
        alias_dict = {
            "mono": "monospace",
            "code": "monospace",
            "sans_serif": "sans",
            "sansserif": "sans",
            "bolditalic": "bold_italic",
            "sansbold": "sans_bold",
            "small_caps": "smallcaps",
            "small": "smallcaps",
            "doublestruck": "double_struck",
            "outline": "double_struck"
        }
        mapped_key = alias_dict.get(style_clean)
        if mapped_key:
            mapping = FONT_MAPS.get(mapped_key)

    # If font_style contains sample unicode characters (e.g. user pasted '𝐥𝐨𝐠' or '𝔩𝔬𝔤' or 'ʟᴏɢ')
    if not mapping:
        for char in font_style:
            for _, f_map in FONT_MAPS.items():
                if char in f_map.values():
                    mapping = f_map
                    break
            if mapping:
                break

    if not mapping:
        return text

    return "".join(mapping.get(c, c) for c in text)


def normalize_log_name(name: str) -> str:
    """Normalizes custom fonts (mathematical bold/sans/script, smallcaps) and separators into lowercase ASCII."""
    import unicodedata
    name = "".join(SMALLCAPS_INVERSE.get(c, c) for c in name)
    return unicodedata.normalize("NFKD", name).lower().strip()


def matches_log_channel(channel_name: str, ch_key: str) -> bool:
    """Smart matching for existing log channels across legacy, standard (log-<name>), and custom formats."""
    cname = normalize_log_name(channel_name)
    config = LOG_CHANNEL_CONFIG.get(ch_key)
    if not config:
        formatted = ch_key.replace("_", "-")
        return formatted in cname or ch_key in cname

    target_name, _, aliases = config

    # 1. Exact match with target name (e.g. "log-messages")
    if cname == target_name or cname == target_name.replace("-", "_"):
        return True

    # 2. Contains full target name (e.g. "🔒-log-messages", "𝚲 | log-messages")
    if target_name in cname or target_name.replace("-", "_") in cname:
        return True

    formatted = ch_key.replace("_", "-")

    # 3. Legacy bot format: contains 𝚲 (or normalized 'λ') and (formatted or alias)
    if "𝚲" in channel_name or "λ" in cname:
        if formatted in cname or ch_key in cname:
            return True
        for alias in aliases:
            if alias in cname:
                return True

    # 4. Standard and custom formatted slug matching (requires 'log', separator, or audit indicator)
    # This prevents false positives on standard community channels like #general or #announcements
    has_log_indicator = any(x in cname for x in ["log", "audit", "|", "•", "·", "𝚲"])
    if has_log_indicator:
        if formatted in cname or ch_key in cname:
            return True
        for alias in aliases:
            if (
                f"log-{alias}" in cname or f"{alias}-log" in cname or
                f"log_{alias}" in cname or f"{alias}_log" in cname or
                f"log {alias}" in cname or f"{alias} log" in cname or
                f"log|{alias}" in cname or f"{alias}|log" in cname or
                f"log•{alias}" in cname or f"{alias}•log" in cname or
                f"· {alias}" in cname or f"| {alias}" in cname or
                f"|{alias}" in cname or f"• {alias}" in cname
            ):
                return True

        # Normalized alphanumeric check when log indicator is present
        cname_clean = re.sub(r"[^a-z0-9]", "", cname)
        key_clean = re.sub(r"[^a-z0-9]", "", ch_key)
        if key_clean and key_clean in cname_clean and ("log" in cname_clean or "audit" in cname_clean):
            return True
        for alias in aliases:
            alias_clean = re.sub(r"[^a-z0-9]", "", alias)
            if alias_clean and alias_clean in cname_clean and ("log" in cname_clean or "audit" in cname_clean):
                return True

    return False

async def log_channel_autocomplete_fn(
    interaction: discord.Interaction,
    current: str
) -> List[app_commands.Choice[str]]:
    current_lower = current.lower().strip()
    matches = []
    for ch_key, ch_topic in FULL_LOG_CHANNELS:
        if not current_lower or current_lower in ch_key.lower() or current_lower in ch_topic.lower():
            display = f"{ch_key} - {ch_topic}"
            if len(display) > 100:
                display = display[:97] + "..."
            matches.append(app_commands.Choice(name=display, value=ch_key))
            if len(matches) >= 25:
                break
    return matches


class SecurityAdmin(commands.Cog, name="security"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        super().__init__()

    def _check_owner(self, interaction: discord.Interaction) -> bool:
        """Enforces that only the server owner can execute critical owner controls."""
        return bot_config.is_guild_owner(interaction.guild, interaction.user.id)

    def _check_admin_or_owner(self, interaction: discord.Interaction) -> bool:
        """Enforces that only the server owner or administrators can manage trusted members."""
        if self._check_owner(interaction):
            return True
        user = interaction.user
        return isinstance(user, discord.Member) and user.guild_permissions.administrator

    def _check_mod(self, interaction: discord.Interaction) -> bool:
        """Enforces moderator, admin, or trusted member permissions."""
        if self._check_owner(interaction):
            return True
        if interaction.guild and bot_config.is_trusted(interaction.guild.id, interaction.user.id):
            return True
        user = interaction.user
        return (
            isinstance(user, discord.Member) and
            (user.guild_permissions.administrator or user.guild_permissions.moderate_members)
        )

    # ==========================================
    # TRUSTED MEMBERS (BYPASS & PERMISSION EXEMPTION)
    # ==========================================
    trusted_group = app_commands.Group(name="trusted", description="Manage guild trusted members (bypass filters & run commands without perms)")

    @trusted_group.command(name="add", description="[Owner/Admin Only] Designate a trusted member (bypasses security & runs commands without perms).")
    @app_commands.describe(user="The member to designate as trusted")
    async def trusted_add(self, interaction: discord.Interaction, user: discord.Member):
        if not self._check_admin_or_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner or Administrators can designate trusted members.", ephemeral=True)
            return

        if user.bot:
            await interaction.response.send_message("❌ Bots cannot be designated as trusted members.", ephemeral=True)
            return

        bot_config.add_trusted_cache(interaction.guild_id, user.id)
        await db.add_trusted_member(interaction.guild_id, user.id, str(user), interaction.user.id)

        embed = discord.Embed(
            title="⭐ Trusted Member Added",
            color=discord.Color.gold(),
            description=(
                f"**{user.mention} (`{user.id}`)** is now a **Trusted Member** in this server!\n\n"
                f"🛡️ **Security Bypass:** Complete exemption from security filters, raid gates, spam blocks, and voice timeouts.\n"
                f"⚡ **Permission Exemption:** Authorized to execute Karuppu bot management commands without native Discord permissions."
            ),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text=f"Authorized by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    @trusted_group.command(name="remove", description="[Owner/Admin Only] Revoke a member's trusted status.")
    @app_commands.describe(user="The member to remove from trusted list")
    async def trusted_remove(self, interaction: discord.Interaction, user: discord.Member):
        if not self._check_admin_or_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner or Administrators can manage trusted members.", ephemeral=True)
            return

        bot_config.remove_trusted_cache(interaction.guild_id, user.id)
        await db.remove_trusted_member(interaction.guild_id, user.id)

        embed = discord.Embed(
            title="🗑️ Trusted Member Removed",
            color=discord.Color.red(),
            description=f"**{user.mention} (`{user.id}`)** has been removed from this server's trusted members list.",
            timestamp=datetime.now(timezone.utc)
        )
        await interaction.response.send_message(embed=embed)

    @trusted_group.command(name="list", description="List all trusted members in this server.")
    async def trusted_list(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator, Administrator, or Trusted Member status required to view list.", ephemeral=True)
            return

        members = await db.get_trusted_members(interaction.guild_id)
        lines = []
        for m in members:
            ts_str = m.get("added_at", "")
            try:
                time_part = f"<t:{int(datetime.fromisoformat(ts_str).timestamp())}:R>" if ts_str else "recently"
            except Exception:
                time_part = "recently"
            lines.append(f"• <@{m['user_id']}> (`{m.get('user_name', m['user_id'])}`) — Added {time_part}")

        embed = discord.Embed(
            title="⭐ Guild Trusted Members",
            color=discord.Color.gold(),
            description=(
                "Trusted members have complete security bypass and can execute bot management commands without requiring native Discord moderator permissions:\n\n" +
                ("\n".join(lines) if lines else "*No trusted members configured yet. Use `/trusted add` to add one.*")
            ),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text=f"Total: {len(members)} trusted members")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ==========================================
    # SERVER ROLE SELECTION & PUBLIC SETUP
    # ==========================================
    async def cmd_set_role(self, interaction: discord.Interaction, gate: app_commands.Choice[str], role: discord.Role):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        await db.update_guild_role_gate(guild_id, gate.value, role.id, role.name)

        # Update cache
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id][f"{gate.value}_role_id"] = role.id
        bot_config.guild_settings_cache[guild_id][f"{gate.value}_role_name"] = role.name

        embed = discord.Embed(
            title="✅ Level Gate Role Updated",
            color=discord.Color.green(),
            description=(
                f"**Permission Gate:** `{gate.name}`\n"
                f"**Required Role:** {role.mention} (`{role.name}`)\n\n"
                f"Members with **{role.name}** (or higher level ranks) can now use this feature!"
            )
        )
        embed.set_footer(text=f"Updated by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    def _check_can_unmute(self, interaction: discord.Interaction) -> tuple[bool, Optional[str]]:
        """Verifies if the user is authorized to reverse server mutes."""
        if self._check_owner(interaction):
            return True, None
        user = interaction.user
        if isinstance(user, discord.Member) and user.guild_permissions.administrator:
            return True, None
        if bot_config.is_trusted(interaction.guild.id, user.id):
            return True, None

        guild_settings = bot_config.guild_settings_cache.get(interaction.guild.id, {})
        allowed_role_id = guild_settings.get("unmute_role_id")
        allowed_role_name = guild_settings.get("unmute_role_name", "Authorized Role")

        if allowed_role_id and isinstance(user, discord.Member):
            if any(r.id == allowed_role_id for r in user.roles):
                return True, None

        return False, allowed_role_name

    async def cmd_set_unmute_role(self, interaction: discord.Interaction, role: discord.Role):
        if not self._check_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner can configure the unmute role.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        await db.set_unmute_role(guild_id, role.id, role.name)

        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id]["unmute_role_id"] = role.id
        bot_config.guild_settings_cache[guild_id]["unmute_role_name"] = role.name

        embed = discord.Embed(
            title="✅ Unmute Authority Role Configured",
            color=discord.Color.green(),
            description=(
                f"**Authorized Role:** {role.mention} (`{role.name}`)\n\n"
                f"Members with **{role.name}** (as well as Server Owner & Administrators) are now authorized to use `/security unmute` to restore voice access if a bot action was incorrect."
            )
        )
        embed.set_footer(text=f"Configured by Server Owner ({interaction.user})")
        await interaction.response.send_message(embed=embed)

    async def cmd_unmute(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        reason: Optional[str] = "False positive / Decision reversed by authorized staff"
    ):
        can_run, req_role = self._check_can_unmute(interaction)
        if not can_run:
            msg = f"❌ **Access Denied**: Only members with the **@{req_role}** role (selected by the Server Owner) or Administrators can reverse server mutes." if req_role else "❌ **Access Denied**: Only the Server Owner or designated roles can reverse server mutes."
            await interaction.response.send_message(msg, ephemeral=True)
            return

        guild = interaction.guild
        me = guild.me
        if not me.guild_permissions.mute_members:
            await interaction.response.send_message("❌ Bot lacks the **'Mute Members'** permission to edit voice states.", ephemeral=True)
            return

        audit_reason = f"Unmuted by {interaction.user}: {reason}"
        changes_applied = []

        # 1. Reverse server mute if active
        if member.voice and member.voice.mute:
            try:
                await member.edit(mute=False, reason=audit_reason)
                changes_applied.append("Voice Server-Mute removed")
            except Exception as e:
                logger.warning("Failed to lift voice mute on %s: %s", member, e)

        # 2. Lift timeout if active
        if member.is_timed_out():
            try:
                await member.timeout(None, reason=audit_reason)
                changes_applied.append("Temporary Timeout lifted")
            except Exception as e:
                logger.warning("Failed to lift timeout on %s: %s", member, e)

        if not changes_applied:
            # If not currently in voice or timed out, attempt voice edit anyway in case state was cached
            try:
                await member.edit(mute=False, reason=audit_reason)
                changes_applied.append("Voice Server-Mute cleared")
            except Exception:
                pass

        if not changes_applied:
            await interaction.response.send_message(
                f"ℹ️ {member.mention} is not currently server-muted or timed out.",
                ephemeral=True
            )
            return

        # Record to audit log database
        await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered="Server Mute Reversal",
            confidence="HIGH (Manual Staff Override)",
            raw_evidence=f"Action by {interaction.user} ({interaction.user.id}) | Reason: {reason}",
            action_taken=f"Reversed mute by {interaction.user}",
            moderator_id=interaction.user.id
        )

        embed = discord.Embed(
            title="🔊 Member Server Mute Reversed",
            color=discord.Color.green(),
            description=(
                f"**Member:** {member.mention} (`{member.id}`)\n"
                f"**Authorized Staff:** {interaction.user.mention}\n"
                f"**Reason:** {reason}\n\n"
                f"✅ **Actions Applied:** {', '.join(changes_applied)}"
            )
        )
        embed.set_footer(text="Security override logged to audit database")
        await interaction.response.send_message(embed=embed)

    def _can_moderate_target(self, interaction: discord.Interaction, target: discord.Member) -> tuple[bool, str]:
        """Validates that the moderator can take action against the target member."""
        if target.id == interaction.user.id:
            return False, "❌ You cannot moderate yourself."
        if bot_config.is_guild_owner(interaction.guild, target.id):
            return False, "❌ You cannot moderate the Server Owner."
        if target.id == self.bot.user.id:
            return False, "❌ You cannot moderate the bot."

        # Role hierarchy check (only applies if moderator is not the server owner)
        if not self._check_owner(interaction):
            mod_user = interaction.user
            if isinstance(mod_user, discord.Member):
                if target.top_role >= mod_user.top_role:
                    return False, f"❌ You cannot moderate {target.mention} because their highest role is equal to or higher than yours."

        me = interaction.guild.me
        if target.top_role >= me.top_role:
            return False, f"❌ Bot cannot moderate {target.mention} because their highest role is equal to or higher than the bot's highest role."

        return True, ""

    # ==========================================
    # VOICE CHANNEL MODERATION: KICK, TIMEOUT & BAN
    # ==========================================
    # Voice Moderation Actions (Internal / Panel & /voice Actions)
    async def cmd_vc_kick(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        reason: Optional[str] = "Voice Channel Moderation Kick"
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        can_mod, err_msg = self._can_moderate_target(interaction, member)
        if not can_mod:
            await interaction.response.send_message(err_msg, ephemeral=True)
            return

        guild = interaction.guild
        me = guild.me
        if not me.guild_permissions.move_members:
            await interaction.response.send_message("❌ Bot lacks the **'Move Members'** permission to disconnect members.", ephemeral=True)
            return

        if not member.voice or not member.voice.channel:
            await interaction.response.send_message(f"❌ {member.mention} is not currently connected to any voice channel.", ephemeral=True)
            return

        await interaction.response.defer()

        try:
            vc_channel = member.voice.channel
            channel_name = vc_channel.name

            try:
                await member.move_to(None, reason=f"VC Kick by {interaction.user}: {reason}")
            except Exception as e:
                await interaction.followup.send(f"❌ Failed to disconnect member: `{e}`")
                return

            await db.log_incident(
                guild_id=guild.id,
                user_id=member.id,
                username=str(member),
                rule_triggered="Voice Channel Kick",
                confidence="HIGH (Staff Action)",
                raw_evidence=f"Kicked from #{channel_name} by {interaction.user} ({interaction.user.id}) | Reason: {reason}",
                action_taken=f"VC Kick by {interaction.user}",
                moderator_id=interaction.user.id
            )

            embed = discord.Embed(
                title="🔌 Member Kicked from Voice",
                color=discord.Color.orange(),
                description=(
                    f"**Member:** {member.mention} (`{member.id}`)\n"
                    f"**Disconnected From:** `#{channel_name}`\n"
                    f"**Moderator:** {interaction.user.mention}\n"
                    f"**Reason:** {reason}"
                ),
                timestamp=datetime.now(timezone.utc)
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            embed.set_footer(text="VC moderation action logged")
            await interaction.followup.send(embed=embed)

            log_ch_id = bot_config.get_log_channel_id(guild.id, "mod") or bot_config.get_log_channel_id(guild.id, "voice")
            if log_ch_id and log_ch_id != interaction.channel_id:
                ch = guild.get_channel(log_ch_id)
                if isinstance(ch, discord.TextChannel):
                    try:
                        await ch.send(embed=embed)
                    except Exception:
                        pass
        except Exception as e:
            logger.exception("Error executing cmd_vc_kick: %s", e)
            await interaction.followup.send(f"❌ Error executing VC kick: `{e}`", ephemeral=True)

    async def cmd_vc_timeout(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        duration_minutes: int,
        reason: Optional[str] = "Voice Channel Moderation Timeout"
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        if duration_minutes <= 0 or duration_minutes > 43200:
            await interaction.response.send_message("❌ Duration must be between 1 minute and 43,200 minutes (30 days).", ephemeral=True)
            return

        can_mod, err_msg = self._can_moderate_target(interaction, member)
        if not can_mod:
            await interaction.response.send_message(err_msg, ephemeral=True)
            return

        guild = interaction.guild
        me = guild.me
        if not me.guild_permissions.move_members:
            await interaction.response.send_message("❌ Bot lacks the **'Move Members'** permission to disconnect members.", ephemeral=True)
            return

        await interaction.response.defer()

        try:
            now_utc = datetime.now(timezone.utc)
            expires_at = now_utc + timedelta(minutes=duration_minutes)
            expires_iso = expires_at.isoformat()

            # Disconnect if currently in voice
            vc_name = "None"
            if member.voice and member.voice.channel:
                vc_name = member.voice.channel.name
                try:
                    await member.move_to(None, reason=f"VC Timeout by {interaction.user}: {reason}")
                except Exception:
                    pass

            # Apply voice server mute if bot has permission
            if me.guild_permissions.mute_members:
                try:
                    await member.edit(mute=True, reason=f"VC Timeout: {reason}")
                except Exception:
                    pass

            # Apply channel connect=False overwrites across voice channels
            if guild.me.guild_permissions.manage_channels:
                for vc in guild.voice_channels + guild.stage_channels:
                    try:
                        await vc.set_permissions(member, connect=False, speak=False, reason=f"VC Timeout: {reason}")
                    except Exception:
                        pass

            await db.add_vc_punishment(
                guild_id=guild.id,
                user_id=member.id,
                punishment_type="timeout",
                moderator_id=interaction.user.id,
                reason=reason,
                expires_at=expires_iso
            )
            bot_config.vc_punishments_cache[(guild.id, member.id)] = {
                "punishment_type": "timeout",
                "reason": reason,
                "expires_at": expires_iso,
                "moderator_id": interaction.user.id
            }

            await db.log_incident(
                guild_id=guild.id,
                user_id=member.id,
                username=str(member),
                rule_triggered="Voice Channel Timeout",
                confidence="HIGH (Staff Action)",
                raw_evidence=f"Timed out for {duration_minutes}m by {interaction.user} | Active VC: #{vc_name} | Reason: {reason}",
                action_taken=f"VC Timeout ({duration_minutes}m)",
                moderator_id=interaction.user.id
            )

            try:
                dm_embed = discord.Embed(
                    title=f"⏳ You have been timed out from Voice Channels in {guild.name}",
                    color=discord.Color.red(),
                    description=(
                        f"**Duration:** `{duration_minutes}` minutes\n"
                        f"**Expires:** <t:{int(expires_at.timestamp())}:R>\n"
                        f"**Reason:** {reason}\n\n"
                        f"You will not be able to join voice channels in **{guild.name}** until the timeout expires."
                    )
                )
                await member.send(embed=dm_embed)
            except Exception:
                pass

            embed = discord.Embed(
                title="⏳ Member Voice Timeout Applied",
                color=discord.Color.red(),
                description=(
                    f"**Member:** {member.mention} (`{member.id}`)\n"
                    f"**Duration:** `{duration_minutes}` minutes (Expires <t:{int(expires_at.timestamp())}:R>)\n"
                    f"**Moderator:** {interaction.user.mention}\n"
                    f"**Reason:** {reason}\n\n"
                    f"🔒 {member.mention} is blocked from all voice channels until the timeout expires."
                ),
                timestamp=now_utc
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            await interaction.followup.send(embed=embed)

            log_ch_id = bot_config.get_log_channel_id(guild.id, "mod") or bot_config.get_log_channel_id(guild.id, "voice")
            if log_ch_id and log_ch_id != interaction.channel_id:
                ch = guild.get_channel(log_ch_id)
                if isinstance(ch, discord.TextChannel):
                    try:
                        await ch.send(embed=embed)
                    except Exception:
                        pass
        except Exception as e:
            logger.exception("Error executing cmd_vc_timeout: %s", e)
            await interaction.followup.send(f"❌ Error applying voice timeout: `{e}`", ephemeral=True)

    async def cmd_vc_untimeout(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        reason: Optional[str] = "Voice timeout lifted by staff"
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await interaction.response.defer()

        try:
            guild = interaction.guild
            removed = await db.remove_vc_punishment(guild.id, member.id, "timeout")
            bot_config.vc_punishments_cache.pop((guild.id, member.id), None)

            me = guild.me
            if me.guild_permissions.mute_members:
                try:
                    await member.edit(mute=False, reason=f"VC Untimeout by {interaction.user}: {reason}")
                except Exception:
                    pass

            # Remove channel connect=False overwrites
            if guild.me.guild_permissions.manage_channels:
                for vc in guild.voice_channels + guild.stage_channels:
                    try:
                        await vc.set_permissions(member, overwrite=None, reason=f"VC Untimeout: {reason}")
                    except Exception:
                        pass

            if not removed:
                await interaction.followup.send(f"ℹ️ {member.mention} does not have an active VC timeout.", ephemeral=True)
                return

            embed = discord.Embed(
                title="🔊 Voice Timeout Removed",
                color=discord.Color.green(),
                description=(
                    f"**Member:** {member.mention} (`{member.id}`)\n"
                    f"**Moderator:** {interaction.user.mention}\n"
                    f"**Reason:** {reason}\n\n"
                    f"✅ Voice channel access has been fully restored."
                ),
                timestamp=datetime.now(timezone.utc)
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            await interaction.followup.send(embed=embed)
        except Exception as e:
            logger.exception("Error executing cmd_vc_untimeout: %s", e)
            await interaction.followup.send(f"❌ Error lifting voice timeout: `{e}`", ephemeral=True)

    async def cmd_vc_ban(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        reason: Optional[str] = "Voice Channel Moderation Ban",
        duration_hours: Optional[int] = None,
        scope: Optional[Union[app_commands.Choice[str], str]] = None
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        can_mod, err_msg = self._can_moderate_target(interaction, member)
        if not can_mod:
            await interaction.response.send_message(err_msg, ephemeral=True)
            return

        guild = interaction.guild
        me = guild.me
        if not me.guild_permissions.move_members:
            await interaction.response.send_message("❌ Bot lacks the **'Move Members'** permission to disconnect members.", ephemeral=True)
            return

        await interaction.response.defer()

        try:
            scope_val = scope.value if hasattr(scope, "value") else (scope or "server")
            target_guild_id = 0 if scope_val == "global" else guild.id
            is_global = target_guild_id == 0

            now_utc = datetime.now(timezone.utc)
            expires_iso = None
            duration_str = "Permanent"
            if duration_hours and duration_hours > 0:
                expires_at = now_utc + timedelta(hours=duration_hours)
                expires_iso = expires_at.isoformat()
                duration_str = f"{duration_hours} hours (Expires <t:{int(expires_at.timestamp())}:R>)"

            # Disconnect if currently in voice
            if member.voice and member.voice.channel:
                try:
                    await member.move_to(None, reason=f"VC Ban by {interaction.user}: {reason}")
                except Exception:
                    pass

            # Apply voice server mute
            if me.guild_permissions.mute_members:
                try:
                    await member.edit(mute=True, reason=f"VC Ban: {reason}")
                except Exception:
                    pass

            # Apply channel connect=False overwrites across voice channels
            if guild.me.guild_permissions.manage_channels:
                for vc in guild.voice_channels + guild.stage_channels:
                    try:
                        await vc.set_permissions(member, connect=False, speak=False, reason=f"VC Ban: {reason}")
                    except Exception:
                        pass

            await db.add_vc_punishment(
                guild_id=target_guild_id,
                user_id=member.id,
                punishment_type="ban",
                moderator_id=interaction.user.id,
                reason=reason,
                expires_at=expires_iso
            )
            bot_config.vc_punishments_cache[(target_guild_id, member.id)] = {
                "punishment_type": "ban",
                "reason": reason,
                "expires_at": expires_iso,
                "moderator_id": interaction.user.id
            }

            scope_label = "🌐 Global (All Servers)" if is_global else "🏢 Server-Wide"
            await db.log_incident(
                guild_id=guild.id,
                user_id=member.id,
                username=str(member),
                rule_triggered="Voice Channel Ban",
                confidence="HIGH (Staff Action)",
                raw_evidence=f"VC Banned ({duration_str} | {scope_label}) by {interaction.user} | Reason: {reason}",
                action_taken=f"VC Ban ({duration_str} | {scope_label})",
                moderator_id=interaction.user.id
            )

            try:
                dm_embed = discord.Embed(
                    title=f"🔨 You have been banned from Voice Channels in {guild.name}",
                    color=discord.Color.dark_red(),
                    description=(
                        f"**Duration:** {duration_str}\n"
                        f"**Scope:** {scope_label}\n"
                        f"**Reason:** {reason}\n\n"
                        f"You are strictly prohibited from joining voice channels."
                    )
                )
                await member.send(embed=dm_embed)
            except Exception:
                pass

            embed = discord.Embed(
                title=f"🔨 Member Banned from Voice Channels ({scope_label})",
                color=discord.Color.dark_red(),
                description=(
                    f"**Member:** {member.mention} (`{member.id}`)\n"
                    f"**Duration:** {duration_str}\n"
                    f"**Scope:** `{scope_label}`\n"
                    f"**Moderator:** {interaction.user.mention}\n"
                    f"**Reason:** {reason}\n\n"
                    f"🚫 {member.mention} is blocked from connecting to voice channels."
                ),
                timestamp=now_utc
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            await interaction.followup.send(embed=embed)

            log_ch_id = bot_config.get_log_channel_id(guild.id, "mod") or bot_config.get_log_channel_id(guild.id, "voice")
            if log_ch_id and log_ch_id != interaction.channel_id:
                ch = guild.get_channel(log_ch_id)
                if isinstance(ch, discord.TextChannel):
                    try:
                        await ch.send(embed=embed)
                    except Exception:
                        pass
        except Exception as e:
            logger.exception("Error executing cmd_vc_ban: %s", e)
            await interaction.followup.send(f"❌ Error applying voice ban: `{e}`", ephemeral=True)

    async def cmd_vc_unban(
        self,
        interaction: discord.Interaction,
        user: discord.User,
        reason: Optional[str] = "Voice ban revoked by staff"
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await interaction.response.defer()

        try:
            guild = interaction.guild
            removed = await db.remove_vc_punishment(guild.id, user.id, "ban")
            removed_global = await db.remove_vc_punishment(0, user.id, "ban")
            bot_config.vc_punishments_cache.pop((guild.id, user.id), None)
            bot_config.vc_punishments_cache.pop((0, user.id), None)

            member = guild.get_member(user.id)
            if member and guild.me.guild_permissions.mute_members:
                try:
                    await member.edit(mute=False, reason=f"VC Unban by {interaction.user}: {reason}")
                except Exception:
                    pass

            # Remove channel connect=False overwrites
            if guild.me.guild_permissions.manage_channels and member:
                for vc in guild.voice_channels + guild.stage_channels:
                    try:
                        await vc.set_permissions(member, overwrite=None, reason=f"VC Unban: {reason}")
                    except Exception:
                        pass

            if not (removed or removed_global):
                await interaction.followup.send(f"ℹ️ {user.mention} is not currently VC banned.", ephemeral=True)
                return

            embed = discord.Embed(
                title="✅ Voice Channel Ban Revoked",
                color=discord.Color.green(),
                description=(
                    f"**User:** {user.mention} (`{user.id}`)\n"
                    f"**Moderator:** {interaction.user.mention}\n"
                    f"**Reason:** {reason}\n\n"
                    f"Voice channel ban has been lifted. User can now join voice channels."
                ),
                timestamp=datetime.now(timezone.utc)
            )
            embed.set_thumbnail(url=user.display_avatar.url)
            await interaction.followup.send(embed=embed)
        except Exception as e:
            logger.exception("Error executing cmd_vc_unban: %s", e)
            await interaction.followup.send(f"❌ Error revoking voice ban: `{e}`", ephemeral=True)

    async def cmd_vc_banlist(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        try:
            guild = interaction.guild
            punishments = await db.get_active_vc_punishments(guild.id)

            if not punishments:
                await interaction.followup.send("ℹ️ There are no active voice channel bans or timeouts in this server.", ephemeral=True)
                return

            lines = []
            now_utc = datetime.now(timezone.utc)
            for p in punishments:
                u_id = p["user_id"]
                p_type = p["punishment_type"].upper()
                icon = "🔨" if p_type == "BAN" else "⏳"
                reason = p.get("reason", "No reason provided")
                exp_str = p.get("expires_at")
                if exp_str:
                    try:
                        exp_dt = datetime.fromisoformat(exp_str)
                        if now_utc >= exp_dt:
                            continue  # Expired
                        duration_part = f"Expires <t:{int(exp_dt.timestamp())}:R>"
                    except Exception:
                        duration_part = "Temporary"
                else:
                    duration_part = "**Permanent**"

                lines.append(f"{icon} **{p_type}** | <@{u_id}> (`{u_id}`)\n└ {duration_part} • *\"{reason}\"*")

            if not lines:
                await interaction.followup.send("ℹ️ There are no active voice channel bans or timeouts in this server.", ephemeral=True)
                return

            embed = discord.Embed(
                title=f"🛡️ Active Voice Punishments ({len(lines)})",
                color=discord.Color.dark_red(),
                description="\n\n".join(lines[:15]),
                timestamp=now_utc
            )
            if len(lines) > 15:
                embed.set_footer(text=f"Showing 15 of {len(lines)} active voice punishments")
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            logger.exception("Error executing cmd_vc_banlist: %s", e)
            await interaction.followup.send(f"❌ Error fetching active voice punishments: `{e}`", ephemeral=True)

    # ==========================================
    # 24/7 VOICE GUARD CONNECTION COMMANDS (Internal / Panel & /voice Actions)
    # ==========================================
    async def cmd_vc_guard_join(self, interaction: discord.Interaction, channel: Optional[discord.VoiceChannel] = None):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        target_channel = channel

        if not target_channel:
            if interaction.user.voice and interaction.user.voice.channel:
                target_channel = interaction.user.voice.channel
            else:
                await interaction.response.send_message("❌ Please specify a voice channel, or join a voice channel first!", ephemeral=True)
                return

        me = guild.me
        perms = target_channel.permissions_for(me)
        if not perms.connect:
            await interaction.response.send_message(f"❌ Bot lacks permission to connect to {target_channel.mention}.", ephemeral=True)
            return

        await interaction.response.defer()

        try:
            vc = guild.voice_client
            if vc and vc.is_connected():
                if vc.channel.id == target_channel.id:
                    await interaction.followup.send(f"🛡️ Voice Guard is already active and connected in {target_channel.mention}!")
                    return
                await vc.move_to(target_channel)
            else:
                await target_channel.connect(self_deaf=True)

            # Persist to database so it auto-reconnects on reboot
            await db.set_guard_voice_channel(guild.id, target_channel.id)
            if guild.id not in bot_config.guild_settings_cache:
                bot_config.guild_settings_cache[guild.id] = {}
            bot_config.guild_settings_cache[guild.id]["guard_voice_channel_id"] = target_channel.id

            embed = discord.Embed(
                title="🛡️ Voice Guard Connected & Active",
                color=discord.Color.green(),
                description=(
                    f"**Karuppu** is now connected and guarding {target_channel.mention}!\n\n"
                    f"• **24/7 Persistence**: Saved as the default Voice Guard channel. The bot will automatically stay and reconnect here after restarts.\n"
                    f"• **Active Protection**: Guarding against mic glitch macros, notification chime spam, and raid surges.\n"
                    f"• **Disconnect Anytime**: Use `/security vc_guard leave`."
                )
            )
            embed.set_footer(text=f"Activated by {interaction.user}")
            await interaction.followup.send(embed=embed)
        except Exception as e:
            logger.error("Failed to connect Voice Guard to %s: %s", target_channel.name, e)
            await interaction.followup.send(f"❌ Failed to connect Voice Guard: `{e}`")

    async def cmd_vc_guard_leave(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        vc = guild.voice_client

        # Clear from database
        await db.set_guard_voice_channel(guild.id, None)
        if guild.id in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild.id]["guard_voice_channel_id"] = None

        if not vc or not vc.is_connected():
            await interaction.response.send_message("ℹ️ Voice Guard is not currently connected to any voice channel in this server.", ephemeral=True)
            return

        channel_name = vc.channel.name
        try:
            await vc.disconnect(force=True)
            embed = discord.Embed(
                title="🔌 Voice Guard Disconnected",
                color=discord.Color.orange(),
                description=f"Voice Guard was disconnected from **#{channel_name}** and cleared from 24/7 auto-connect."
            )
            embed.set_footer(text=f"Disconnected by {interaction.user}")
            await interaction.response.send_message(embed=embed)
        except Exception as e:
            await interaction.response.send_message(f"❌ Failed to disconnect: `{e}`", ephemeral=True)

    async def cmd_vc_guard_status(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        vc = guild.voice_client
        settings = bot_config.guild_settings_cache.get(guild.id, {})
        saved_ch_id = settings.get("guard_voice_channel_id")
        saved_ch = guild.get_channel(saved_ch_id) if saved_ch_id else None

        embed = discord.Embed(
            title="🛡️ Voice Guard Status",
            color=discord.Color.blue()
        )
        if vc and vc.is_connected():
            embed.add_field(name="Current Channel", value=f"{vc.channel.mention} (`#{vc.channel.name}`)", inline=True)
            embed.add_field(name="State", value="🟢 Connected & Guarding", inline=True)
            embed.add_field(name="Members in Room", value=f"`{len(vc.channel.members) - 1}` active members", inline=True)
        else:
            embed.add_field(name="Current State", value="⚪ Not Connected", inline=True)

        embed.add_field(
            name="24/7 Saved Channel",
            value=saved_ch.mention if saved_ch else "*None (connect with `/security vc_guard join`)*",
            inline=False
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def cmd_set_alert_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        await db.set_alert_channel(guild_id, channel.id)

        # Update cache
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id]["alert_channel_id"] = channel.id

        embed = discord.Embed(
            title="📢 Alert Channel Updated",
            color=discord.Color.blue(),
            description=f"Security alerts, raid cards, and scam notifications will now be posted to {channel.mention}."
        )
        embed.set_footer(text=f"Configured by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    FULL_LOG_CHANNELS = FULL_LOG_CHANNELS

    async def cmd_set_log_channel(self, interaction: discord.Interaction, category: str, channel: discord.TextChannel):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        cat_val = category.strip().lower()
        guild_id = interaction.guild.id
        await db.set_dedicated_log_channel(guild_id, cat_val, channel.id)
        bot_config.guild_log_channels_cache[(guild_id, cat_val)] = channel.id

        # Also sync to legacy settings if applicable
        legacy_cats = {
            "message": "chat", "chat": "chat",
            "voice": "voice",
            "presence": "vc_state",
            "vc_state": "vc_state",
            "soundboard": "vc_state",
            "member": "member",
            "mod": "mod",
            "server": "server"
        }
        if cat_val in legacy_cats:
            legacy_key = legacy_cats[cat_val]
            await db.set_log_channel(guild_id, legacy_key, channel.id)
            if guild_id not in bot_config.guild_settings_cache:
                bot_config.guild_settings_cache[guild_id] = {}
            bot_config.guild_settings_cache[guild_id][f"{legacy_key}_log_channel_id"] = channel.id

        embed = discord.Embed(
            title="📑 Dedicated Log Channel Configured",
            color=discord.Color.green(),
            description=(
                f"**Category:** `{cat_val}`\n"
                f"**Log Destination:** {channel.mention}\n\n"
                f"All future events for this category will be logged here."
            )
        )
        embed.set_footer(text=f"Configured by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    async def _execute_setup_full_suite(
        self,
        guild: discord.Guild,
        prefix: Optional[str] = None,
        allowed_role: Optional[discord.Role] = None,
        category_name: Optional[str] = None,
        font_style: Optional[str] = None,
        separator: Optional[str] = None,
        **kwargs
    ) -> Tuple[bool, str, Optional[discord.CategoryChannel], int, Optional[discord.Embed]]:
        """Sets up or updates the full 33-channel logging suite with customizable prefix, separator, and fonts.
        Renames existing channels to the new format instead of creating duplicates.
        """
        me = guild.me
        if not me.guild_permissions.manage_channels:
            return False, "Bot lacks the 'Manage Channels' permission.", None, 0, None

        # Determine target category name
        if category_name and category_name.strip():
            target_category_name = category_name.strip()
        elif prefix and prefix.strip() not in ["𝚲", "", "log"]:
            target_category_name = f"📁 {prefix.strip()} Server Logs"
        else:
            target_category_name = "📁 Server Logs"

        # 1. Base Overwrites: Hidden completely from @everyone
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

        # 2. Grant visibility to staff roles (with admin or moderation perms)
        for r in guild.roles:
            if r.permissions.administrator or r.permissions.moderate_members or r.permissions.manage_guild:
                overwrites[r] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

        if allowed_role:
            overwrites[allowed_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

        try:
            # Check if category already exists; if not, create it
            category = None
            for cat in guild.categories:
                cname = cat.name.lower()
                if (
                    cname == target_category_name.lower()
                    or "server logs" in cname
                    or "𝚲 logs" in cname
                    or "log" in cname
                    or "𝚲" in cat.name
                ):
                    category = cat
                    break

            if category:
                try:
                    if "𝚲" in category.name or category.name.lower() in ["logs", "server logs", "𝚲 logs"]:
                        await category.edit(name=target_category_name, overwrites=overwrites)
                    else:
                        await category.edit(overwrites=overwrites)
                except Exception as cat_err:
                    logger.warning("Could not update category %s: %s", category.name, cat_err)
            else:
                category = await guild.create_category(target_category_name, overwrites=overwrites, reason="Automated 32-channel logging suite setup")

            created_channels = {}
            db_map = {}
            cat_channels = list(category.text_channels)
            guild_channels = list(guild.text_channels)
            claimed_channel_ids = set()
            renamed_count = 0
            created_count = 0

            has_custom = (
                prefix is not None or
                separator is not None or
                (font_style and font_style.strip().lower() not in ["normal", "none", "standard", "default", ""])
            )
            pref = prefix.strip() if prefix is not None else "log"
            sep = separator.strip() if separator is not None else "-"
            if not sep and pref:
                sep = "-"

            for ch_key, ch_topic in self.FULL_LOG_CHANNELS:
                config = LOG_CHANNEL_CONFIG.get(ch_key, (f"log-{ch_key.replace('_', '-')}", ch_topic, [ch_key]))
                core_name = ch_key.replace("_", "-")

                if has_custom:
                    styled_core = apply_font(core_name, font_style) if font_style else core_name
                    if pref:
                        target_name = f"{pref}{sep}{styled_core}"
                    else:
                        target_name = f"{styled_core}"
                else:
                    target_name = config[0]

                target_name = target_name[:100]

                # 1. Check if already bound in cache
                ch = None
                cached_id = bot_config.get_log_channel_id(guild.id, ch_key)
                if cached_id and cached_id not in claimed_channel_ids:
                    cached_ch = guild.get_channel(cached_id)
                    if isinstance(cached_ch, discord.TextChannel):
                        ch = cached_ch

                # 2. Smart match against existing channels inside the category
                if not ch:
                    for existing_ch in cat_channels:
                        if existing_ch.id not in claimed_channel_ids and matches_log_channel(existing_ch.name, ch_key):
                            ch = existing_ch
                            break

                # 3. Smart match across all guild text channels
                if not ch:
                    for existing_ch in guild_channels:
                        if existing_ch.id not in claimed_channel_ids and matches_log_channel(existing_ch.name, ch_key):
                            ch = existing_ch
                            break

                if ch:
                    claimed_channel_ids.add(ch.id)
                    # Channel exists! Rename & update if needed
                    edit_kwargs = {}
                    if ch.name != target_name:
                        edit_kwargs["name"] = target_name
                    if ch.topic != ch_topic:
                        edit_kwargs["topic"] = ch_topic
                    if ch.category_id != category.id:
                        edit_kwargs["category"] = category

                    if edit_kwargs:
                        try:
                            await ch.edit(**edit_kwargs)
                            renamed_count += 1
                            await asyncio.sleep(0.35)
                        except Exception as edit_err:
                            logger.warning("Could not rename/move channel %s (%s): %s", ch.name, ch_key, edit_err)
                else:
                    # Missing channel, create fresh with target_name
                    try:
                        ch = await guild.create_text_channel(
                            target_name,
                            category=category,
                            topic=ch_topic,
                            reason=f"Automated logging suite setup ({ch_key})"
                        )
                        created_count += 1
                        claimed_channel_ids.add(ch.id)
                        await asyncio.sleep(0.35)
                    except Exception as create_err:
                        logger.warning("Could not create channel %s: %s", target_name, create_err)

                if ch:
                    created_channels[ch_key] = ch
                    db_map[ch_key] = ch.id
                    bot_config.guild_log_channels_cache[(guild.id, ch_key)] = ch.id

            # Bulk persist to database
            await db.bulk_set_log_channels(guild.id, db_map)

            # Sync legacy log channel IDs
            legacy_sync = {
                "chat_log_channel_id": db_map.get("message"),
                "voice_log_channel_id": db_map.get("voice"),
                "vc_state_log_channel_id": db_map.get("vc_state") or db_map.get("soundboard") or db_map.get("voice"),
                "member_log_channel_id": db_map.get("member"),
                "mod_log_channel_id": db_map.get("mod"),
                "server_log_channel_id": db_map.get("server")
            }
            if guild.id not in bot_config.guild_settings_cache:
                bot_config.guild_settings_cache[guild.id] = {}
            for k, v in legacy_sync.items():
                if v:
                    bot_config.guild_settings_cache[guild.id][k] = v

            sec_ch_id = db_map.get("security")
            if sec_ch_id:
                await db.set_alert_channel(guild.id, sec_ch_id)
                bot_config.guild_settings_cache[guild.id]["alert_channel_id"] = sec_ch_id

            # Post Welcome & Orientation card in the security log channel
            welcome_target = created_channels.get("security") or created_channels.get("mod") or (list(created_channels.values())[0] if created_channels else None)
            total_count = len(self.FULL_LOG_CHANNELS)
            if welcome_target:
                welcome_embed = discord.Embed(
                    title="𓆩『 SERVER LOGGING SUITE ACTIVE 』𓆪",
                    color=discord.Color.from_rgb(88, 101, 242),
                    description=(
                        f"Welcome to the **Server Logging Suite** for **{guild.name}**!\n\n"
                        f"All **{total_count} dedicated security log channels** are active, locked, and auto-bound to Karuppu's audit engine.\n\n"
                        f"🔒 **Visibility:** Hidden from `@everyone` • Authorized Staff Only\n"
                        f"⚡ **Active Channels:** `{len(created_channels)}/{total_count}` Channels Online\n"
                        f"🏷️ **Channel Format:** `log-<name>` (Standardized Clean Slugs)\n"
                        f"🛡️ **Complete Coverage:** Voice, VC Status, Text, Stage, Events, Announcements, Roles, Server & Moderation."
                    ),
                    timestamp=datetime.now(timezone.utc)
                )
                welcome_embed.set_footer(text="Karuppu Security & Audit Suite")
                try:
                    await welcome_target.send(embed=welcome_embed)
                except Exception:
                    pass

            # Summary to moderator
            reply_embed = discord.Embed(
                title=f"🎉 Complete {total_count}-Channel Logging Suite Updated!",
                color=discord.Color.green(),
                description=(
                    f"Successfully updated logging suite in category **`{category.name}`**!\n\n"
                    f"• **Category:** `{category.name}`\n"
                    f"• **Channel Naming:** `log-<name>` (Standardized Clean Slugs)\n"
                    f"• **Channels Renamed/Updated:** **{renamed_count}** existing channels updated\n"
                    f"• **Channels Created:** **{created_count}** new channels created\n"
                    f"• **Total Active Channels:** **{len(created_channels)}/{total_count}** online\n"
                    f"• **Coverage:** VC, VC Status, Text, Stage, Events, Announcements, Kicks, Bans, Timeouts, Roles, Emojis & Server changes\n"
                    f"• **Access:** Server Administrators & allowed staff roles only\n"
                    f"• **Auto-Binding:** 100% connected & routed to database & audit engine\n\n"
                    f"*(All channels are organized cleanly under `{category.name}`!)*"
                ),
                timestamp=datetime.now(timezone.utc)
            )
            if allowed_role:
                reply_embed.add_field(name="Extra Staff Role Granted", value=allowed_role.mention, inline=False)

            return True, "", category, len(created_channels), reply_embed
        except Exception as e:
            logger.exception("Failed _execute_setup_full_suite: %s", e)
            return False, str(e), None, 0, None

    async def sync_existing_log_channels(
        self,
        guild: discord.Guild,
        prefix: Optional[str] = None
    ) -> Tuple[int, Optional[discord.CategoryChannel], Dict[str, discord.TextChannel], List[str]]:
        """100% Read-Only / Zero-Creation Sync:
        Binds existing Discord log channels to Karuppu's audit cache and SQLite database without creating any categories or channels.
        """
        category = None
        for cat in guild.categories:
            cname = cat.name.lower()
            if "server logs" in cname or "𝚲 logs" in cname or "log" in cname or "𝚲" in cat.name or "security" in cname:
                category = cat
                break

        channels_to_inspect = list(category.text_channels) if category else list(guild.text_channels)
        bound_channels = {}
        db_map = {}
        missing = []
        claimed_ids = set()

        for ch_key, ch_topic in self.FULL_LOG_CHANNELS:
            matched_ch = None

            # 1. Try cached ID first
            cached_id = bot_config.get_log_channel_id(guild.id, ch_key)
            if cached_id and cached_id not in claimed_ids:
                cached_ch = guild.get_channel(cached_id)
                if isinstance(cached_ch, discord.TextChannel):
                    matched_ch = cached_ch

            # 2. Check inside detected category
            if not matched_ch:
                for ch in channels_to_inspect:
                    if ch.id not in claimed_ids and matches_log_channel(ch.name, ch_key):
                        matched_ch = ch
                        break

            # 3. Fallback across all guild text channels
            if not matched_ch and category:
                for ch in guild.text_channels:
                    if ch.id not in claimed_ids and matches_log_channel(ch.name, ch_key):
                        matched_ch = ch
                        break

            if matched_ch:
                claimed_ids.add(matched_ch.id)
                bound_channels[ch_key] = matched_ch
                db_map[ch_key] = matched_ch.id
                bot_config.guild_log_channels_cache[(guild.id, ch_key)] = matched_ch.id
            else:
                missing.append(ch_key)

        # Bulk persist to database if any were found
        if db_map:
            await db.bulk_set_log_channels(guild.id, db_map)
            legacy_sync = {
                "chat_log_channel_id": db_map.get("message"),
                "voice_log_channel_id": db_map.get("voice"),
                "vc_state_log_channel_id": db_map.get("vc_state") or db_map.get("soundboard") or db_map.get("voice"),
                "member_log_channel_id": db_map.get("member"),
                "mod_log_channel_id": db_map.get("mod"),
                "server_log_channel_id": db_map.get("server")
            }
            if guild.id not in bot_config.guild_settings_cache:
                bot_config.guild_settings_cache[guild.id] = {}
            for k, v in legacy_sync.items():
                if v:
                    bot_config.guild_settings_cache[guild.id][k] = v

        return len(bound_channels), category, bound_channels, missing

    @commands.command(name="logsync", aliases=["synclogs", "sync_logs", "log_sync"])
    async def msg_cmd_logsync(self, ctx: commands.Context, *, args: Optional[str] = None):
        """Prefix command (!logsync or !log sync) that binds existing channels without creating new ones."""
        is_allowed = (
            ctx.author.id == ctx.guild.owner_id or
            bot_config.is_trusted(ctx.guild.id, ctx.author.id) or
            ctx.author.guild_permissions.administrator or
            ctx.author.guild_permissions.manage_guild or
            ctx.author.guild_permissions.moderate_members
        )
        if not is_allowed:
            await ctx.reply("❌ Administrator or Moderator permissions required to run this command.")
            return

        status_msg = await ctx.reply("🔄 **Scanning existing server channels and binding log routes (Zero creation mode)...**")
        count, category, bound, missing = await self.sync_existing_log_channels(ctx.guild)
        total = len(self.FULL_LOG_CHANNELS)
        cat_desc = f"`{category.name}`" if category else "*Server Text Channels (No category)*"
        embed = discord.Embed(
            title="🔄 Log Channels Synced (Zero-Creation Mode)",
            color=discord.Color.green(),
            description=(
                f"**Audit & Logging Engine Synced!**\n\n"
                f"📁 **Log Category:** {cat_desc}\n"
                f"⚡ **Channels Bound:** `{count}/{total}` active log channels\n"
                f"🛡️ **Zero-Creation Guarantee:** **0** new categories created, **0** new channels created.\n\n"
                f"✅ All {count} existing channels are bound and actively receiving log events!"
            ),
            timestamp=datetime.now(timezone.utc)
        )
        if bound:
            sample = [f"• `{k}` ➔ {ch.mention}" for k, ch in list(bound.items())[:12]]
            embed.add_field(name="Bound Channels (Sample)", value="\n".join(sample), inline=False)
        embed.set_footer(text="Karuppu Log Sync Engine")
        await status_msg.edit(content=None, embed=embed)

    @commands.command(name="logs", aliases=["setup_logs", "setuplogs", "setup"])
    @commands.has_permissions(administrator=True)
    async def msg_cmd_logs(self, ctx: commands.Context, *, args: Optional[str] = None):
        """Prefix command (!logs or !setup) to update or create all 32 logging channels with log- prefix."""
        is_allowed = (
            ctx.author.id == ctx.guild.owner_id or
            bot_config.is_trusted(ctx.guild.id, ctx.author.id) or
            ctx.author.guild_permissions.administrator or
            ctx.author.guild_permissions.manage_guild or
            ctx.author.guild_permissions.moderate_members
        )
        if not is_allowed:
            await ctx.reply("❌ Administrator or Moderator permissions required to set up/update logs.")
            return

        status_msg = await ctx.reply("⚙️ **Updating & syncing all 32 dedicated log channels with `log-` prefix... Please wait a few seconds!**")
        success, err, category, count, embed = await self._execute_setup_full_suite(ctx.guild)
        if success and embed:
            cat_name = category.name if category else "Server Logs"
            await status_msg.edit(content=f"✅ **Logging suite in `{cat_name}` updated! ({count}/32 channels ready)**", embed=embed)
        else:
            await status_msg.edit(content=f"❌ Failed creating/updating logging suite: `{err}`")

    async def _handle_setup_full_suite(
        self,
        interaction: discord.Interaction,
        prefix: Optional[str] = None,
        allowed_role: Optional[discord.Role] = None,
        category_name: Optional[str] = None,
        font_style: Optional[str] = None,
        separator: Optional[str] = None,
        **kwargs
    ) -> Tuple[bool, str, Optional[discord.CategoryChannel], int, Optional[discord.Embed]]:
        """Worker that defers interaction, performs permission checks, and triggers category/channel generation or updates."""
        if not interaction.response.is_done():
            await interaction.response.defer(ephemeral=True)

        if not self._check_mod(interaction):
            await interaction.followup.send("❌ Moderator permissions required.", ephemeral=True)
            return False, "Moderator permissions required.", None, 0, None

        guild = interaction.guild
        if not guild:
            await interaction.followup.send("❌ This command can only be used in a server.", ephemeral=True)
            return False, "This command can only be used in a server.", None, 0, None

        me = guild.me
        if not me.guild_permissions.manage_channels:
            await interaction.followup.send("❌ Bot lacks the **'Manage Channels'** permission to create or edit channels.", ephemeral=True)
            return False, "Bot lacks Manage Channels permission.", None, 0, None

        success, err, category, count, embed = await self._execute_setup_full_suite(
            guild,
            prefix=prefix,
            allowed_role=allowed_role,
            category_name=category_name,
            font_style=font_style,
            separator=separator,
            **kwargs
        )
        if success and embed:
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(f"❌ Error setting up logging suite: `{err}`", ephemeral=True)

        return success, err, category, count, embed

    async def cmd_setup(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        g_cfg = bot_config.guild_settings_cache.get(guild.id, {})
        alert_ch_id = g_cfg.get("alert_channel_id", bot_config.alert_channel_id)
        alert_ch_str = f"<#{alert_ch_id}>" if alert_ch_id else "*Not configured (run `/security set_alert_channel`)*"

        def _format_gate(gate_name, default_name):
            r_id = g_cfg.get(f"{gate_name}_role_id")
            r_name = g_cfg.get(f"{gate_name}_role_name")
            if r_id:
                return f"<@&{r_id}> (`{r_name}`)"
            return f"`{default_name}` *(Default)*"

        def _format_ch(category):
            c_id = g_cfg.get(f"{category}_log_channel_id")
            return f"<#{c_id}>" if c_id else "*Not set*"

        embed = discord.Embed(
            title=f"🛡️ Security Configuration: {guild.name}",
            color=discord.Color.blue(),
            description="Here are the active security gates and role requirements for this server:"
        )
        embed.add_field(name="📢 Moderator Alert Channel", value=alert_ch_str, inline=False)
        embed.add_field(
            name="🔒 Configured Level Gates",
            value=(
                f"• **External Links & URLs:** {_format_gate('links', 'Guild Recruit')}\n"
                f"• **GIFs & Media:** {_format_gate('media', 'Guild Recruit')}\n"
                f"• **ZIP / RAR Archives:** {_format_gate('archives', 'Bronze Rank')}\n"
                f"• **Server Invites:** {_format_gate('invites', 'Bronze Rank')}"
            ),
            inline=False
        )
        embed.add_field(
            name="📑 Dedicated Log Channels",
            value=(
                f"• **Chat Logs (Edits/Deletes):** {_format_ch('chat')}\n"
                f"• **Voice Mod Logs (Moves/Mutes/Disconnects):** {_format_ch('voice')}\n"
                f"• **VC State Logs (Self-Mute/Deaf/Video/Sound):** {_format_ch('vc_state')}\n"
                f"• **Member Logs (Join/Leave + Age):** {_format_ch('member')}\n"
                f"• **Mod Logs (Bans/Kicks/Timeouts):** {_format_ch('mod')}\n"
                f"• **Server Logs (Channel/Role Changes):** {_format_ch('server')}"
            ),
            inline=False
        )
        unmute_role_id = g_cfg.get("unmute_role_id")
        unmute_str = f"<@&{unmute_role_id}>" if unmute_role_id else "*None (Owner & Admins only)*"
        embed.add_field(name="🔊 Reverse-Mute Authority Role", value=unmute_str, inline=False)
        embed.add_field(
            name="💡 Quick Tips",
            value=(
                "• Set individual log channels: `/security set_log_channel <category> <channel>`\n"
                "• Auto-create all 5 log channels in 1 click: `/security setup_all_logs`\n"
                "• Type `/help` for the complete guide!"
            ),
            inline=False
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ==========================================
    # MODERATION & OPERATIONAL CONTROLS
    # ==========================================
    async def cmd_lockdown(self, interaction: discord.Interaction, duration_minutes: Optional[int] = 15, reason: Optional[str] = "Emergency Moderation Lockdown"):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required to initiate lockdown.", ephemeral=True)
            return

        duration = min(max(duration_minutes or 15, 1), 120)
        lockdown_cog = self.bot.get_cog("ServerLockdown")
        if not lockdown_cog:
            await interaction.response.send_message("❌ Lockdown module is not loaded.", ephemeral=True)
            return

        await interaction.response.defer()
        success, msg = await lockdown_cog.apply_lockdown(
            guild=interaction.guild,
            duration_minutes=duration,
            reason=reason or "Emergency Lockdown",
            moderator=interaction.user
        )

        if success:
            embed = discord.Embed(
                title="🔒 Emergency Server Lockdown Initiated",
                description=(
                    f"**Duration:** `{duration}` minutes (auto-expiring)\n"
                    f"**Reason:** {reason}\n"
                    f"**Moderator:** {interaction.user.mention}\n\n"
                    f"{msg}\n\n"
                    f"Use `/unlock` to reverse the lockdown at any time."
                ),
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(f"❌ {msg}", ephemeral=True)

    async def cmd_unlock(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        lockdown_cog = self.bot.get_cog("ServerLockdown")
        if not lockdown_cog:
            await interaction.response.send_message("❌ Lockdown module is not loaded.", ephemeral=True)
            return

        await interaction.response.defer()
        success, msg = await lockdown_cog.lift_lockdown(interaction.guild, moderator=interaction.user)
        if success:
            embed = discord.Embed(
                title="🔓 Server Lockdown Reversed",
                description=f"{msg}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.green()
            )
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(f"ℹ️ {msg}", ephemeral=True)

    async def cmd_purge_raid(
        self,
        interaction: discord.Interaction,
        within_minutes: Optional[int] = 15,
        require_no_roles: Optional[bool] = True,
        action: Optional[str] = "kick"
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        minutes = min(max(within_minutes or 15, 1), 60)
        action_type = "ban" if action and action.lower() == "ban" else "kick"
        guild = interaction.guild

        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        candidates = []
        for mem in guild.members:
            if mem.bot or mem.id == guild.owner_id:
                continue
            if bot_config.is_bypassed(guild, mem):
                continue
            # Check join time
            if mem.joined_at and mem.joined_at >= cutoff:
                # If require_no_roles is True, member should only have @everyone role
                if require_no_roles and len(mem.roles) > 1:
                    continue
                candidates.append(mem)

        if not candidates:
            await interaction.response.send_message(
                f"ℹ️ No candidate raid accounts found who joined in the last `{minutes}` minutes.",
                ephemeral=True
            )
            return

        sample_preview = ", ".join([f"<@{m.id}>" for m in candidates[:8]])
        if len(candidates) > 8:
            sample_preview += f" *(and {len(candidates) - 8} more)*"

        embed = discord.Embed(
            title="⚠️ Confirm Raid Purge Execution",
            color=discord.Color.red(),
            description=(
                f"A raid purge scan identified **{len(candidates)} accounts** matching criteria:\n\n"
                f"• **Joined within:** Last `{minutes}` minutes\n"
                f"• **Role Filter:** `{'Zero assigned roles' if require_no_roles else 'Any role'}`\n"
                f"• **Selected Action:** `{action_type.upper()}`\n\n"
                f"**Sample Accounts:** {sample_preview}\n\n"
                f"**Confirm below to execute this action.**"
            )
        )
        view = RaidPurgeConfirmView(candidates=candidates, action_type=action_type, moderator=interaction.user)
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    async def cmd_toggle_dry_run(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        new_val = not bot_config.dry_run
        bot_config.dry_run = new_val
        bot_config.save_yaml()

        status_text = "DRY-RUN MODE (Alerts Only, No Automated Punishments)" if new_val else "ACTIVE ENFORCEMENT (Auto-deleting violations & applying timeouts)"
        color = discord.Color.gold() if new_val else discord.Color.green()

        embed = discord.Embed(
            title="⚙️ Operational Mode Updated",
            description=f"Security bot is now running in:\n**{status_text}**\n\nUpdated by {interaction.user.mention}.",
            color=color
        )
        await interaction.response.send_message(embed=embed)

    async def cmd_status(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        trust_cfg = bot_config.progressive_trust
        link_role = trust_cfg.get("link_gate", {}).get("required_role", "Disabled")
        gif_role = trust_cfg.get("media_and_gif_gate", {}).get("required_role", "Disabled")
        voice_cfg = bot_config.raw_data.get("voice_protection", {})

        embed = discord.Embed(
            title="🛡️ Discord Security Suite Status",
            color=discord.Color.blue()
        )
        embed.add_field(
            name="Operational Mode",
            value=f"`{'DRY RUN (Simulated)' if bot_config.dry_run else 'ACTIVE ENFORCEMENT'}`",
            inline=True
        )
        embed.add_field(name="Bot Latency", value=f"`{round(self.bot.latency * 1000)}ms`", inline=True)
        embed.add_field(name="Guilds Monitored", value=f"`{len(self.bot.guilds)}`", inline=True)

        embed.add_field(
            name="Progressive Trust (Level Gates)",
            value=(
                f"• **Links:** Requires `{link_role}`\n"
                f"• **GIFs/Media:** Requires `{gif_role}`\n"
                f"• **Bypass Control:** Exclusively Server Owner"
            ),
            inline=False
        )

        # Threats enabled
        embed.add_field(
            name="Threat Modules",
            value=(
                f"• **Anti-Raid Detector:** `{'Enabled' if bot_config.raid_detector.get('enabled') else 'Disabled'}`\n"
                f"• **Anti-Nuke Protection:** `{'Enabled' if bot_config.anti_nuke.get('enabled', True) else 'Disabled'}`\n"
                f"• **Anti-Spam (10 Msg Cap):** `{'Enabled' if bot_config.spam_detector.get('enabled') else 'Disabled'}`\n"
                f"• **Phishing Filter:** `{'Enabled' if bot_config.phishing_detector.get('enabled') else 'Disabled'}`\n"
                f"• **Voice Channel Defense:** `{'Enabled' if voice_cfg.get('enabled') else 'Disabled'}`"
            ),
            inline=False
        )
        embed.set_footer(text=f"Requested by {interaction.user}")
        await interaction.response.send_message(embed=embed, ephemeral=True)


class ShortCommands(commands.Cog):
    """Ultra-fast, short slash commands for daily Discord moderation."""
    def __init__(self, bot: commands.Bot, admin: SecurityAdmin):
        self.bot = bot
        self.admin = admin

    async def _call(self, cmd_target, *args, **kwargs):
        """Safely delegates execution to the underlying coroutine of app_commands.Command or regular functions."""
        if hasattr(cmd_target, "callback"):
            return await cmd_target.callback(self.admin, *args, **kwargs)
        return await cmd_target(*args, **kwargs)

    @app_commands.command(name="logs", description="[Admins Only] Open 33-channel logging control embed or run 1-click setup.")
    @app_commands.describe(
        action="Leave empty to open control embed, or select 'setup' to run setup directly",
        prefix="Optional tag prefix (e.g. 'log', '𝚲')",
        separator="Optional separator between prefix and channel name (e.g. '-', '|', '•')",
        font_style="Optional font style (normal, bold, sans, italic, monospace, smallcaps, or sample text)",
        allowed_role="Optional: Extra staff/moderator role allowed to see these private log channels"
    )
    @app_commands.choices(
        action=[
            app_commands.Choice(name="Open Dashboard Embed", value="dashboard"),
            app_commands.Choice(name="Run Full 33-Channel Setup", value="setup")
        ],
        font_style=[
            app_commands.Choice(name="Normal / Standard (default)", value="normal"),
            app_commands.Choice(name="Bold (𝐛𝐨𝐥𝐝)", value="bold"),
            app_commands.Choice(name="Sans-Serif (𝗌𝖺𝗇𝗌)", value="sans"),
            app_commands.Choice(name="Sans-Serif Bold (𝘀𝗮𝗻𝘀)", value="sans_bold"),
            app_commands.Choice(name="Monospace (𝚖𝚘𝚗𝚘)", value="monospace"),
            app_commands.Choice(name="Italic (𝘪𝘵𝘢𝘭𝘪𝘤)", value="italic"),
            app_commands.Choice(name="Small Caps (ꜱᴍᴀʟʟ)", value="smallcaps"),
        ]
    )
    async def cmd_short_logs(
        self,
        interaction: discord.Interaction,
        action: Optional[str] = None,
        prefix: Optional[str] = "𝚲",
        separator: Optional[str] = None,
        font_style: Optional[str] = None,
        allowed_role: Optional[discord.Role] = None
    ):
        if action != "setup" and prefix == "𝚲" and separator is None and font_style is None and allowed_role is None:
            from src.cogs.control_center import LogsControlView
            total = len(self.admin.FULL_LOG_CHANNELS)
            bound = sum(1 for k, _ in self.admin.FULL_LOG_CHANNELS if (interaction.guild.id, k) in bot_config.guild_log_channels_cache)
            alert_id = bot_config.get_alert_channel_id(interaction.guild.id)
            alert_str = f"<#{alert_id}>" if alert_id else "*None set*"
            embed = discord.Embed(
                title="📜 33-Channel Audit & Logging Suite Hub",
                color=discord.Color.green() if bound >= total else discord.Color.gold(),
                description=(
                    f"**Coverage:** `{bound}/{total}` active log channels online\n"
                    f"**Alert Channel:** {alert_str}\n"
                    f"**Bot Command Tracking:** Dedicated `#log-bot-commands` channel with proxy attribution\n\n"
                    f"👉 **Click '1-Click Setup'** below to configure prefix, font, separator, and channels,\n"
                    f"or click **'Zero-Creation Sync'** to bind existing channels."
                ),
                timestamp=datetime.now(timezone.utc)
            )
            embed.set_footer(text="Karuppu Audit & Logging Engine")
            view = LogsControlView(self.bot, interaction.guild)
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
            return
        await self.admin._handle_setup_full_suite(
            interaction,
            prefix=prefix,
            allowed_role=allowed_role,
            separator=separator,
            font_style=font_style
        )

    async def cmd_short_vcban(self, interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = None, duration_hours: Optional[int] = None):
        await self._call(self.admin.cmd_vc_ban, interaction, member=member, reason=reason, duration_hours=duration_hours)

    async def cmd_short_vcunban(self, interaction: discord.Interaction, user: discord.User, reason: Optional[str] = None):
        await self._call(self.admin.cmd_vc_unban, interaction, user=user, reason=reason)

    async def cmd_short_vckick(self, interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = None):
        await self._call(self.admin.cmd_vc_kick, interaction, member=member, reason=reason)

    async def cmd_short_vctimeout(self, interaction: discord.Interaction, member: discord.Member, duration_minutes: int, reason: Optional[str] = None):
        await self._call(self.admin.cmd_vc_timeout, interaction, member=member, duration_minutes=duration_minutes, reason=reason)

    async def cmd_short_vcuntimeout(self, interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = None):
        await self._call(self.admin.cmd_vc_untimeout, interaction, member=member, reason=reason)

    async def cmd_short_vcbans(self, interaction: discord.Interaction):
        await self._call(self.admin.cmd_vc_banlist, interaction)

    async def cmd_short_lock(self, interaction: discord.Interaction, duration_minutes: Optional[int] = 30, reason: Optional[str] = "Emergency containment"):
        await self._call(self.admin.cmd_lockdown, interaction, duration_minutes=duration_minutes, reason=reason)

    async def cmd_short_unlock(self, interaction: discord.Interaction):
        await self._call(self.admin.cmd_unlock, interaction)

    async def cmd_short_purge(self, interaction: discord.Interaction, within_minutes: Optional[int] = 15, action: Optional[str] = "ban"):
        await self._call(self.admin.cmd_purge_raid, interaction, within_minutes=within_minutes, action=action)

    async def cmd_short_setlog(self, interaction: discord.Interaction, category: str, channel: discord.TextChannel):
        await self._call(self.admin.cmd_set_log_channel, interaction, category=category, channel=channel)

    async def cmd_short_setalert(self, interaction: discord.Interaction, channel: discord.TextChannel):
        await self._call(self.admin.cmd_set_alert_channel, interaction, channel=channel)

    async def cmd_short_dryrun(self, interaction: discord.Interaction):
        await self._call(self.admin.cmd_toggle_dry_run, interaction)

    async def cmd_short_status(self, interaction: discord.Interaction):
        await self._call(self.admin.cmd_status, interaction)

    @app_commands.command(name="logsync", description="[Admins Only] Zero-creation sync: Binds existing Discord log channels without creating new ones.")
    async def cmd_short_logsync(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if not self.admin._check_mod(interaction):
            await interaction.followup.send("❌ Moderator or Administrator permissions required.", ephemeral=True)
            return

        count, category, bound, missing = await self.admin.sync_existing_log_channels(interaction.guild)
        total = len(self.admin.FULL_LOG_CHANNELS)
        cat_desc = f"`{category.name}`" if category else "*Server Text Channels (No category)*"
        embed = discord.Embed(
            title="🔄 Log Channels Synced (Zero-Creation Mode)",
            color=discord.Color.green(),
            description=(
                f"**Audit & Logging Engine Synced!**\n\n"
                f"📁 **Log Category:** {cat_desc}\n"
                f"⚡ **Channels Bound:** `{count}/{total}` active log channels\n"
                f"🛡️ **Zero-Creation Guarantee:** **0** new categories created, **0** new channels created.\n\n"
                f"✅ All {count} existing channels are bound and actively receiving log events!"
            ),
            timestamp=datetime.now(timezone.utc)
        )
        if bound:
            sample = [f"• `{k}` ➔ {ch.mention}" for k, ch in list(bound.items())[:12]]
            embed.add_field(name="Bound Channels (Sample)", value="\n".join(sample), inline=False)
        embed.set_footer(text="Karuppu Log Sync Engine")
        await interaction.followup.send(embed=embed, ephemeral=True)


async def setup(bot: commands.Bot):
    admin_cog = SecurityAdmin(bot)
    await bot.add_cog(admin_cog)
    await bot.add_cog(ShortCommands(bot, admin_cog))

"""Malicious File Attachment and Dangerous Executable Blocker Cog.
Blocks .exe, .scr, .bat, scripts, archives with double extensions, and gates .zip/.rar behind level roles.
"""
import os
import re
import logging
from typing import List
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.attachment_scanner")

# Dangerous extensions that should never be posted in general chat
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".msi", ".iso",
    ".jar", ".apk", ".ps1", ".sh", ".dll", ".hta", ".wsf", ".cpl"
}

# Archive extensions that low-level accounts frequently abuse for token-loggers
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

# Double extension pattern (e.g. image.png.exe or photo.jpg.scr)
DOUBLE_EXT_REGEX = re.compile(
    r'\.(png|jpg|jpeg|gif|webp|pdf|txt|docx|mp4|mp3)\.(exe|scr|bat|cmd|vbs|msi|ps1|hta)$',
    re.IGNORECASE
)

class AttachmentScanner(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _is_dangerous(self, filename: str) -> bool:
        lower = filename.lower()
        ext = os.path.splitext(lower)[1]
        if ext in DANGEROUS_EXTENSIONS:
            return True
        if DOUBLE_EXT_REGEX.search(lower):
            return True
        return False

    def _is_archive(self, filename: str) -> bool:
        lower = filename.lower()
        ext = os.path.splitext(lower)[1]
        return ext in ARCHIVE_EXTENSIONS

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.bot or not message.attachments:
            return

        member: discord.Member = message.author
        guild = message.guild
        channel = message.channel

        # OWNER-EXCLUSIVE BYPASS
        if bot_config.is_bypassed(guild, member, channel):
            return

        cfg = bot_config.raw_data.get("attachment_security", {})
        if not cfg.get("enabled", True):
            return

        for attachment in message.attachments:
            filename = attachment.filename

            # 1. Block dangerous executable files completely
            if cfg.get("block_executables", True) and self._is_dangerous(filename):
                await self._handle_dangerous_file(message, filename)
                return

            # 2. Archive Gate (ZIP/RAR gated behind level role)
            archive_cfg = cfg.get("archive_gate", {})
            if archive_cfg.get("enabled", True) and self._is_archive(filename):
                required_role = archive_cfg.get("required_role", "Level 5")
                if not bot_config.has_required_role(member, required_role):
                    await self._handle_archive_gate_violation(message, filename, str(required_role), archive_cfg)
                    return

    async def _handle_dangerous_file(self, message: discord.Message, filename: str):
        member = message.author
        guild = message.guild
        dry_run = bot_config.dry_run

        rule_name = "Malicious Attachment: Blocked Executable File"
        action_text = "[DRY RUN] Would delete file & timeout for 1 hour" if dry_run else "Deleted dangerous attachment & applied 1-hour timeout"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered=rule_name,
            confidence="CRITICAL (100% Malicious File Extension)",
            raw_evidence=f"Uploaded dangerous file: '{filename}'",
            action_taken=action_text
        )

        if not dry_run:
            try:
                await message.delete()
            except Exception:
                pass
            try:
                from datetime import timedelta
                await member.timeout(timedelta(hours=1), reason=f"Uploaded suspicious executable: {filename}")
            except Exception as e:
                logger.warning("Failed to timeout user for dangerous attachment: %s", e)

        # Dispatch alert
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"🛑 DANGEROUS FILE ATTACHMENT {'[DRY RUN]' if dry_run else '[BLOCKED]'}",
            color=discord.Color.red(),
            description=f"A potentially harmful executable/script file was uploaded by {member.mention}."
        )
        embed.add_field(name="Member", value=f"{member} (`{member.id}`)", inline=True)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="Filename", value=f"`{filename}`", inline=False)
        embed.add_field(
            name="Recommended Action",
            value="Review account history. If the file was an unrequested game beta/cheat tool, consider banning the account.",
            inline=False
        )
        embed.set_footer(text=f"Incident #{incident_id} • Antigravity Malware Defense")

        view = SecurityAlertView(
            incident_id=incident_id,
            guild_id=guild.id,
            target_user_id=member.id,
            target_username=str(member),
            message_id=message.id if dry_run else None,
            channel_id=message.channel.id
        )
        await alert_channel.send(content="@here" if not dry_run else None, embed=embed, view=view)

    async def _handle_archive_gate_violation(self, message: discord.Message, filename: str, required_role: str, cfg: dict):
        member = message.author
        dry_run = bot_config.dry_run
        reminder = cfg.get(
            "reminder_text",
            "📦 **ZIP and archive uploads unlock at {required_role}!** Keep chatting to earn archive upload privileges."
        ).format(required_role=required_role, user=member.mention)

        incident_id = await db.log_incident(
            guild_id=message.guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered="Progressive Trust: Archive Gate (.zip/.rar)",
            confidence="HIGH (Role Verification)",
            raw_evidence=f"Uploaded archive '{filename}' without role '{required_role}'",
            action_taken="[DRY RUN] Would delete & send reminder" if dry_run else "Deleted archive & sent auto-cleaned reminder"
        )

        if not dry_run:
            try:
                await message.delete()
                await message.channel.send(f"{member.mention} {reminder}", delete_after=6)
            except Exception as e:
                logger.error("Failed handling archive violation: %s", e)

async def setup(bot: commands.Bot):
    await bot.add_cog(AttachmentScanner(bot))

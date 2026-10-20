"""Zalgo Text, Blank Name, and Staff Impersonation Sanitizer Cog.
Sanitizes unreadable, screen-lagging, and deceptive usernames/nicknames on join or profile update.
"""
import unicodedata
import random
import logging
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.name_sanitizer")

ZERO_WIDTH_CHARS = {
    '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
    '\ufeff', '\u2060', '\u2061', '\u2062', '\u2063', '\u2064'
}

class NameSanitizer(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _is_zalgo(self, text: str, threshold: int = 5) -> bool:
        """Detects vertical combining marks that lag Discord UI (Zalgo text)."""
        consecutive_combining = 0
        for ch in text:
            if unicodedata.combining(ch):
                consecutive_combining += 1
                if consecutive_combining >= threshold:
                    return True
            else:
                consecutive_combining = 0
        return False

    def _is_blank_or_invisible(self, text: str) -> bool:
        """Detects zero-width or unprintable names."""
        cleaned = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS and not ch.isspace())
        return len(cleaned) == 0

    def _is_staff_impersonation(self, guild: discord.Guild, member: discord.Member, name: str) -> bool:
        """Checks if a regular member is copying the server owner or administrator names."""
        if bot_config.is_bypassed(guild, member):
            return False

        owner = guild.owner
        if owner and member.id != owner.id:
            # Check owner's global name, username, and nickname
            owner_names = {owner.name.lower(), owner.display_name.lower()}
            if name.lower() in owner_names:
                return True

        return False

    async def _audit_and_sanitize(self, member: discord.Member):
        if member.bot or not member.guild:
            return

        guild = member.guild
        if bot_config.is_bypassed(guild, member):
            return

        name = member.display_name
        violation = None

        if self._is_blank_or_invisible(name):
            violation = "Invisible / Zero-Width Display Name"
        elif self._is_zalgo(name):
            violation = "Zalgo / Screen-Lagging Unicode Combining Characters"
        elif self._is_staff_impersonation(guild, member, name):
            violation = "Server Staff / Owner Impersonation Name"

        if violation:
            clean_nick = f"Moderated Nickname #{random.randint(1000, 9999)}"
            dry_run = bot_config.dry_run

            incident_id = await db.log_incident(
                guild_id=guild.id,
                user_id=member.id,
                username=str(member),
                rule_triggered=f"Name Sanitizer: {violation}",
                confidence="HIGH (Unicode / Name Audit)",
                raw_evidence=f"Original display name: '{name}'",
                action_taken=f"[DRY RUN] Would rename to {clean_nick}" if dry_run else f"Sanitized nickname to {clean_nick}"
            )

            if not dry_run:
                try:
                    await member.edit(nick=clean_nick, reason=f"[Name Sanitizer] {violation}")
                except discord.Forbidden:
                    logger.warning("Bot lacks 'Manage Nicknames' permission or member has higher role than bot: %s", member)
                except Exception as e:
                    logger.error("Failed to rename member %s: %s", member, e)

            # Alert channel
            alert_ch_id = bot_config.alert_channel_id
            if alert_ch_id:
                alert_ch = self.bot.get_channel(alert_ch_id)
                if alert_ch:
                    embed = discord.Embed(
                        title=f"🏷️ NAME SANITIZED {'[DRY RUN]' if dry_run else ''}",
                        color=discord.Color.blue(),
                        description=f"A member's display name was flagged for: **{violation}**."
                    )
                    embed.add_field(name="Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                    embed.add_field(name="Previous Name", value=f"`{name}`", inline=True)
                    embed.add_field(name="Assigned Name", value=f"`{clean_nick}`", inline=True)
                    embed.set_footer(text=f"Incident #{incident_id} • Antigravity Profile Defense")
                    await alert_ch.send(embed=embed)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        cfg = bot_config.raw_data.get("name_sanitizer", {})
        if cfg.get("enabled", True):
            await self._audit_and_sanitize(member)

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        cfg = bot_config.raw_data.get("name_sanitizer", {})
        if cfg.get("enabled", True) and before.display_name != after.display_name:
            await self._audit_and_sanitize(after)

async def setup(bot: commands.Bot):
    await bot.add_cog(NameSanitizer(bot))

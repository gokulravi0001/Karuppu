"""Progressive Trust / Tiered Permission Gate Cog.
Enforces role/level requirements for links, GIFs, and media attachments with owner-exclusive bypasses.
"""
import re
import logging
from typing import Optional
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.trust_gate")

URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'`]+',
    re.IGNORECASE
)

GIF_DOMAINS = ("tenor.com", "giphy.com", "imgur.com", "gfycat.com")

class ProgressiveTrustGate(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _contains_url(self, content: str) -> bool:
        return bool(URL_REGEX.search(content))

    def _contains_gif_or_media(self, message: discord.Message) -> bool:
        # Check uploaded file attachments
        if message.attachments:
            return True
        # Check stickers
        if message.stickers:
            return True
        # Check Tenor/Giphy GIF URLs
        content_lower = message.content.lower()
        for domain in GIF_DOMAINS:
            if domain in content_lower:
                return True
        return False

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        # Ignore DMs, bots, and system messages
        if not message.guild or message.author.bot:
            return

        member: discord.Member = message.author
        guild: discord.Guild = message.guild
        channel = message.channel

        # 1. OWNER-EXCLUSIVE BYPASS CHECK
        if bot_config.is_bypassed(guild, member, channel):
            return

        cfg = bot_config.progressive_trust
        if not cfg.get("enabled", True):
            return

        # 2. CHECK GIF & MEDIA GATE FIRST (If message contains media or GIF)
        media_cfg = cfg.get("media_and_gif_gate", {})
        if media_cfg.get("enabled", True) and self._contains_gif_or_media(message):
            required_role = media_cfg.get("required_role", "Level 3")
            if not bot_config.has_required_role(member, required_role):
                await self._handle_violation(
                    message=message,
                    rule_name="Progressive Trust: Media / GIF Gate",
                    required_role=str(required_role),
                    custom_msg=media_cfg.get("reminder_text", "🎨 GIFs and attachments unlock at {required_role}! Keep chatting to earn media permissions."),
                    feedback_secs=media_cfg.get("feedback_seconds", 6)
                )
                return

        # 3. CHECK LINK GATE (If message contains URLs)
        link_cfg = cfg.get("link_gate", {})
        if link_cfg.get("enabled", True) and self._contains_url(message.content):
            required_role = link_cfg.get("required_role", "Level 5")
            if not bot_config.has_required_role(member, required_role):
                await self._handle_violation(
                    message=message,
                    rule_name="Progressive Trust: Link Gate",
                    required_role=str(required_role),
                    custom_msg=link_cfg.get("reminder_text", "🔒 Links are unlocked at {required_role}! Keep chatting to level up and share links."),
                    feedback_secs=link_cfg.get("feedback_seconds", 6)
                )
                return

    async def _handle_violation(
        self,
        message: discord.Message,
        rule_name: str,
        required_role: str,
        custom_msg: str,
        feedback_secs: int
    ):
        member = message.author
        guild = message.guild
        dry_run = bot_config.dry_run

        formatted_msg = custom_msg.format(required_role=required_role, user=member.mention)
        action_text = "[DRY RUN] Would delete message & send reminder" if dry_run else "Deleted message & sent auto-cleaned reminder"

        # Record to audit database
        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered=rule_name,
            confidence="HIGH (100% Deterministic Role Check)",
            raw_evidence=message.content,
            action_taken=action_text
        )

        if dry_run:
            logger.info("[DRY RUN] %s triggered by %s (ID: %d) in #%s", rule_name, member, member.id, message.channel.name)
            # Send alert to mod channel if configured
            await self._dispatch_mod_alert(message, incident_id, rule_name, required_role)
        else:
            # Live enforcement
            try:
                await message.delete()
                # Send polite, auto-deleting educational notice
                await message.channel.send(
                    f"{member.mention} {formatted_msg}",
                    delete_after=feedback_secs
                )
            except discord.Forbidden:
                logger.warning("Bot lacks 'Manage Messages' permission to delete message in #%s", message.channel.name)
            except Exception as e:
                logger.error("Failed to delete message: %s", e)

    async def _dispatch_mod_alert(
        self,
        message: discord.Message,
        incident_id: int,
        rule_name: str,
        required_role: str
    ):
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"🔒 {rule_name} [DRY RUN]",
            color=discord.Color.gold(),
            description=f"Member attempted an action requiring **{required_role}**."
        )
        embed.add_field(name="Member", value=f"{message.author.mention} (`{message.author.id}`)", inline=True)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="Required Role", value=f"`{required_role}`", inline=True)
        
        # Redacted preview for privacy
        content_preview = (message.content[:150] + "...") if len(message.content) > 150 else (message.content or "[Attachment/Media Only]")
        embed.add_field(name="Content Preview", value=f"```{content_preview}```", inline=False)
        embed.set_footer(text=f"Incident #{incident_id} • Server Owner Bypasses Apply")

        view = SecurityAlertView(
            incident_id=incident_id,
            guild_id=message.guild.id,
            target_user_id=message.author.id,
            target_username=str(message.author),
            message_id=message.id,
            channel_id=message.channel.id
        )
        await alert_channel.send(embed=embed, view=view)

async def setup(bot: commands.Bot):
    await bot.add_cog(ProgressiveTrustGate(bot))

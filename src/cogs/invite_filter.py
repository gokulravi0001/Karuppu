"""Discord Invite Link Gate and Anti-Server Poaching Cog.
Differentiates between internal guild invites and external server promotions.
Gates external invites behind level roles and allowed channels.
"""
import re
import logging
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.invite_filter")

# Matches discord.gg/code, discord.com/invite/code, discordapp.com/invite/code
INVITE_REGEX = re.compile(
    r'(?:https?://)?(?:www\.)?(?:discord\.(?:gg|io|me|li)|discord(?:app)?\.com/invite)/([a-zA-Z0-9\-]+)',
    re.IGNORECASE
)

class InviteFilter(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.bot:
            return

        member: discord.Member = message.author
        guild = message.guild
        channel = message.channel

        # OWNER-EXCLUSIVE BYPASS
        if bot_config.is_bypassed(guild, member, channel):
            return

        cfg = bot_config.raw_data.get("invite_filter", {})
        if not cfg.get("enabled", True):
            return

        codes = INVITE_REGEX.findall(message.content)
        if not codes:
            return

        # Check if channel is an allowlisted advertising channel
        allowed_channels = cfg.get("allowed_channels", [])
        if channel.id in allowed_channels:
            return

        for code in codes:
            is_external = True
            try:
                # Fetch invite metadata to inspect target guild ID
                invite = await self.bot.fetch_invite(code)
                if invite.guild and invite.guild.id == guild.id:
                    is_external = False  # Safe: invite points to our own server!
            except discord.NotFound:
                # Invalid or expired invite code, still treat as external promo attempt
                is_external = True
            except Exception as e:
                logger.debug("Could not resolve invite code %s: %s", code, e)
                is_external = True

            if is_external:
                # Check required level role for external server invites
                required_role = cfg.get("required_role", "Level 10")
                if not bot_config.has_required_role(member, required_role):
                    await self._handle_unauthorized_invite(message, code, str(required_role), cfg)
                    return

    async def _handle_unauthorized_invite(self, message: discord.Message, code: str, required_role: str, cfg: dict):
        member = message.author
        guild = message.guild
        dry_run = bot_config.dry_run

        reminder = cfg.get(
            "reminder_text",
            "🚫 **Discord server invites unlock at {required_role}!** Server promotion is restricted to prevent spam."
        ).format(required_role=required_role, user=member.mention)

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered="Anti-Self-Promo: External Discord Invite Link",
            confidence="HIGH (Resolved External Server Code)",
            raw_evidence=f"Posted invite code '{code}' in #{message.channel.name}",
            action_taken="[DRY RUN] Would delete invite & send reminder" if dry_run else "Deleted external invite & sent auto-cleaned reminder"
        )

        if not dry_run:
            try:
                await message.delete()
                await message.channel.send(f"{member.mention} {reminder}", delete_after=6)
            except Exception as e:
                logger.error("Failed to delete external invite: %s", e)

        # Dispatch alert card
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"📢 EXTERNAL SERVER INVITE {'[DRY RUN]' if dry_run else '[BLOCKED]'}",
            color=discord.Color.gold() if dry_run else discord.Color.orange(),
            description=f"{member.mention} posted an external Discord server invite."
        )
        embed.add_field(name="Member", value=f"{member} (`{member.id}`)", inline=True)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="Invite Code", value=f"`discord.gg/{code}`", inline=True)
        embed.add_field(
            name="Recommended Action",
            value=f"Member does not possess `{required_role}`. If member is advertising repeatedly, consider a temporary timeout.",
            inline=False
        )
        embed.set_footer(text=f"Incident #{incident_id} • Antigravity Invite Gate")

        view = SecurityAlertView(
            incident_id=incident_id,
            guild_id=guild.id,
            target_user_id=member.id,
            target_username=str(member),
            message_id=message.id if dry_run else None,
            channel_id=message.channel.id
        )
        await alert_channel.send(embed=embed, view=view)

async def setup(bot: commands.Bot):
    await bot.add_cog(InviteFilter(bot))

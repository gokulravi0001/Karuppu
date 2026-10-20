"""Compromised Account / Hacked Friend Anomaly Detector Cog.
Detects hijacked accounts spreading token-stealers, game beta scams, and cross-channel broadcast waves.
"""
import time
import re
import logging
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, Tuple, Set
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.account_anomaly")

# Common social-engineering phishing lures used by token-stealers
COMPROMISED_LURE_PATTERNS = [
    re.compile(r'(?:test|try|play)\s+my\s+(?:new\s+)?game', re.IGNORECASE),
    re.compile(r'vote\s+for\s+(?:my|our)\s+(?:team|clan|csgo|cs2|valorant)', re.IGNORECASE),
    re.compile(r'(?:free|won|giveaway)\s+(?:nitro|\$50|\$100|steam\s+gift)', re.IGNORECASE),
    re.compile(r'need\s+(?:1|one)\s+(?:more\s+)?vote', re.IGNORECASE),
    re.compile(r'i\s+made\s+a\s+game\s+in\s+unity', re.IGNORECASE),
    re.compile(r'download\s+and\s+(?:test|rate)', re.IGNORECASE)
]

URL_REGEX = re.compile(r'(?:https?://|www\.)[^\s<>"\'`]+', re.IGNORECASE)

class CompromisedAccountDetector(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # user_id -> deque of (timestamp, channel_id, has_url)
        self.user_channel_broadcasts: Dict[int, Deque[Tuple[float, int, bool]]] = defaultdict(deque)

    def _matches_compromised_lure(self, content: str) -> bool:
        has_url = bool(URL_REGEX.search(content))
        if not has_url:
            return False
        for pattern in COMPROMISED_LURE_PATTERNS:
            if pattern.search(content):
                return True
        return False

    def _check_cross_channel_link_spread(self, user_id: int, channel_id: int, has_url: bool, window_secs: int = 20) -> int:
        now = time.time()
        history = self.user_channel_broadcasts[user_id]
        history.append((now, channel_id, has_url))

        # Prune events older than window
        while history and (now - history[0][0]) > window_secs:
            history.popleft()

        # Count distinct channels where user posted links within the window
        link_channels: Set[int] = {ch_id for (_, ch_id, u_has_url) in history if u_has_url}
        return len(link_channels)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.bot or not message.content:
            return

        member: discord.Member = message.author
        guild = message.guild
        channel = message.channel

        # OWNER-EXCLUSIVE BYPASS
        if bot_config.is_bypassed(guild, member, channel):
            return

        cfg = bot_config.raw_data.get("compromised_account_guard", {})
        if not cfg.get("enabled", True):
            return

        content = message.content
        has_url = bool(URL_REGEX.search(content))

        # 1. Check for token-stealer social engineering lure patterns
        is_lure = self._matches_compromised_lure(content)

        # 2. Check cross-channel link dispersion rate
        distinct_channel_count = self._check_cross_channel_link_spread(member.id, channel.id, has_url)

        is_cross_channel_spread = distinct_channel_count >= 3

        if is_lure or is_cross_channel_spread:
            confidence = "CRITICAL (98%)" if (is_lure and is_cross_channel_spread) else ("HIGH (90%)" if is_lure else "HIGH (85%)")
            reason = "Compromised Account: Game Beta / Token-Logger Lure Detected" if is_lure else f"Compromised Account: Cross-Channel Link Wave ({distinct_channel_count} channels in 20s)"
            await self._handle_compromised_incident(message, reason, confidence)

    async def _handle_compromised_incident(self, message: discord.Message, reason: str, confidence: str):
        member = message.author
        guild = message.guild
        dry_run = bot_config.dry_run

        action_text = "[DRY RUN] Compromised Account Alert Sent to Mods" if dry_run else "Deleted Message & Applied 1-Hour Quarantine Timeout"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered=reason,
            confidence=confidence,
            raw_evidence=message.content,
            action_taken=action_text
        )

        if not dry_run:
            try:
                await message.delete()
            except Exception:
                pass
            try:
                await member.timeout(timedelta(hours=1), reason=f"[Compromised Account Guard] {reason}")
            except Exception as e:
                logger.warning("Failed to timeout potentially compromised account %s: %s", member, e)

        # Dispatch alert
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"🚨 POTENTIAL COMPROMISED ACCOUNT {'[DRY RUN]' if dry_run else '[CONTAINED]'}",
            color=discord.Color.red(),
            description=(
                f"**{member.mention}** (`{member.id}`) exhibited behavior typical of a hijacked/token-logged account.\n\n"
                f"**Detection:** {reason}\n"
                f"**Confidence:** `{confidence}`"
            )
        )
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        preview = (message.content[:150] + "...") if len(message.content) > 150 else message.content
        embed.add_field(name="Suspicious Message", value=f"```{preview}```", inline=False)
        embed.add_field(
            name="Recommended Action",
            value="Check with this member on an alternate channel or mutual server. If their account was hacked, advise them to reset password/2FA before lifting timeout.",
            inline=False
        )
        embed.set_footer(text=f"Incident #{incident_id} • Account Takeover Shield")

        view = SecurityAlertView(
            incident_id=incident_id,
            guild_id=guild.id,
            target_user_id=member.id,
            target_username=str(member),
            message_id=message.id if dry_run else None,
            channel_id=message.channel.id
        )
        await alert_channel.send(content="@here" if not dry_run else None, embed=embed, view=view)

async def setup(bot: commands.Bot):
    await bot.add_cog(CompromisedAccountDetector(bot))

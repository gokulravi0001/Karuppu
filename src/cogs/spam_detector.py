"""Spam, Rapid Burst, Copypasta, and Mass Mention Detector Cog."""
import time
import hashlib
import logging
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, Tuple
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.spam_detector")

class SpamDetector(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # user_id -> deque of timestamps
        self.user_message_times: Dict[int, Deque[float]] = defaultdict(deque)
        # user_id -> deque of (timestamp, content_hash)
        self.user_copypasta_history: Dict[int, Deque[Tuple[float, str]]] = defaultdict(deque)
        # user_id -> deque of (timestamp, content_hash) for identical message ceiling (10 max)
        self.user_identical_messages: Dict[int, Deque[Tuple[float, str]]] = defaultdict(deque)
        # channel_id -> deque of (timestamp, content_hash)
        self.channel_identical_messages: Dict[int, Deque[Tuple[float, str]]] = defaultdict(deque)

    def _normalize_text(self, text: str) -> str:
        """Strips whitespace, converts to lower case, and removes punctuation for duplicate detection."""
        return "".join(ch for ch in text.lower() if ch.isalnum())

    def _check_identical_ceiling(
        self,
        user_id: int,
        channel_id: int,
        content: str,
        max_allowed: int = 10,
        window_secs: int = 60
    ) -> Tuple[bool, int]:
        """Ensures that no message can be sent more than max_allowed (10) times."""
        norm = self._normalize_text(content) or content.strip().lower()
        if not norm:
            return False, 0

        content_hash = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        now = time.time()

        # Check user history
        user_history = self.user_identical_messages[user_id]
        user_history.append((now, content_hash))
        while user_history and (now - user_history[0][0]) > window_secs:
            user_history.popleft()

        user_count = sum(1 for (t, h) in user_history if h == content_hash)
        if user_count > max_allowed:
            return True, user_count

        # Check channel history
        ch_history = self.channel_identical_messages[channel_id]
        ch_history.append((now, content_hash))
        while ch_history and (now - ch_history[0][0]) > window_secs:
            ch_history.popleft()

        ch_count = sum(1 for (t, h) in ch_history if h == content_hash)
        if ch_count > max_allowed:
            return True, ch_count

        return False, user_count

    def _check_burst(self, user_id: int, burst_limit: int, burst_window: int) -> bool:
        now = time.time()
        times = self.user_message_times[user_id]
        times.append(now)
        # Prune older than sustained window (15s)
        while times and (now - times[0]) > 15:
            times.popleft()

        recent = [t for t in times if (now - t) <= burst_window]
        return len(recent) >= burst_limit

    def _check_copypasta(self, user_id: int, content: str, threshold: int, min_chars: int) -> bool:
        norm = self._normalize_text(content)
        if len(norm) < min_chars:
            return False  # Ignore short chat like 'gg', 'lol', emojis

        content_hash = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        now = time.time()
        history = self.user_copypasta_history[user_id]
        history.append((now, content_hash))

        # Prune older than 30s
        while history and (now - history[0][0]) > 30:
            history.popleft()

        matching = [h for (t, h) in history if h == content_hash]
        return len(matching) >= threshold

    def _count_mentions(self, message: discord.Message) -> int:
        """Counts total distinct user and role mentions."""
        return len(message.mentions) + len(message.role_mentions)

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

        cfg = bot_config.spam_detector
        if not cfg.get("enabled", True):
            return

        burst_limit = int(cfg.get("burst_message_limit", 5))
        burst_window = int(cfg.get("burst_window_seconds", 4))
        copypasta_limit = int(cfg.get("copypasta_threshold", 4))
        copypasta_min_chars = int(cfg.get("copypasta_min_chars", 10))
        mention_limit = int(cfg.get("mass_mentions_threshold", 4))
        max_identical = int(cfg.get("max_identical_messages", 10))
        identical_window = int(cfg.get("identical_window_seconds", 60))

        violation = None
        confidence = "HIGH (90%)"

        # 1. Check Repeated Message Ceiling (No message sent more than 10 times)
        if message.content:
            over_limit, count = self._check_identical_ceiling(member.id, channel.id, message.content, max_identical, identical_window)
            if over_limit:
                violation = f"Message Sent Over 10 Times ({count} duplicates in {identical_window}s)"
                confidence = "HIGH (100% Deterministic)"

        # 2. Check Mass Mentions
        if not violation:
            mentions_count = self._count_mentions(message)
            if mentions_count >= mention_limit:
                violation = f"Mass Mention ({mentions_count} pings in one message)"
                confidence = "HIGH (98%)"
            elif message.mention_everyone and not member.guild_permissions.mention_everyone:
                violation = "Unauthorized @everyone/@here ping attempt"
                confidence = "HIGH (100%)"

        # 3. Check Copypasta / Duplicate Spam
        if not violation and message.content:
            if self._check_copypasta(member.id, message.content, copypasta_limit, copypasta_min_chars):
                violation = f"Duplicate Copypasta Spam ({copypasta_limit}+ identical messages in 30s)"

        # 4. Check Message Burst Rate
        if not violation:
            if self._check_burst(member.id, burst_limit, burst_window):
                violation = f"Rapid Message Burst ({burst_limit}+ messages in {burst_window}s)"

        if violation:
            await self._handle_spam_incident(message, violation, confidence)

    async def _handle_spam_incident(self, message: discord.Message, rule_name: str, confidence: str):
        member = message.author
        guild = message.guild
        dry_run = bot_config.dry_run
        auto_timeout = int(bot_config.spam_detector.get("auto_timeout_seconds", 300))

        action_taken = "[DRY RUN] Alert Dispatched" if dry_run else f"Deleted message & Applied {auto_timeout // 60}m Timeout"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered=rule_name,
            confidence=confidence,
            raw_evidence=message.content,
            action_taken=action_taken
        )

        if not dry_run:
            # Active enforcement
            try:
                await message.delete()
            except Exception:
                pass

            try:
                await member.timeout(timedelta(seconds=auto_timeout), reason=f"[Security Bot] {rule_name}")
            except Exception as e:
                logger.warning("Could not timeout %s: %s", member, e)

        # Dispatch alert card to mod log
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"⚠️ {rule_name} {'[DRY RUN]' if dry_run else '[ENFORCED]'}",
            color=discord.Color.gold() if dry_run else discord.Color.red(),
            description=f"Automated detection flagged suspicious behavior from {member.mention}."
        )
        embed.add_field(name="Offender", value=f"{member} (`{member.id}`)", inline=True)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="Confidence", value=f"`{confidence}`", inline=True)

        preview = (message.content[:150] + "...") if len(message.content) > 150 else (message.content or "[No text preview]")
        embed.add_field(name="Sample Evidence", value=f"```{preview}```", inline=False)
        embed.add_field(
            name="Recommended Action",
            value="Review offender interaction history. Apply a timeout or dismiss if conversation was benign.",
            inline=False
        )
        embed.set_footer(text=f"Incident #{incident_id} • Status: {'Needs Review' if dry_run else 'Auto-Action Applied'}")

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
    await bot.add_cog(SpamDetector(bot))

"""Phishing, Scam, and Suspicious Link Filter Cog.
Detects homoglyphs, brand spoofing, and unwhitelisted lookalike URLs.
"""
import re
import urllib.parse
import unicodedata
import logging
from datetime import timedelta
from typing import List, Optional, Tuple
import discord
from discord.ext import commands
import Levenshtein
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.link_filter")

# Cyrillic and lookalike confusable mapping
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's',
    'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n',
    'ԛ': 'q', 'ԁ': 'd', 'ԍ': 'g', 'һ': 'h', 'ѵ': 'v', 'ԝ': 'w',
    '0': 'o', '1': 'l', '@': 'a', '$': 's'
}

URL_REGEX = re.compile(r'(?:https?://|www\.)([^\s<>"\'`]+)', re.IGNORECASE)

class LinkFilter(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _normalize_homoglyphs(self, text: str) -> str:
        """Converts lookalike unicode, Cyrillic glyphs, and visual digraphs (cl->d, rn->m) to Latin."""
        normalized = unicodedata.normalize('NFKD', text)
        result = []
        for ch in normalized:
            result.append(HOMOGLYPH_MAP.get(ch, ch))
        norm_str = "".join(result).lower()
        # Handle visual digraph confusable tricks in sans-serif fonts
        norm_str = norm_str.replace("cl", "d").replace("rn", "m").replace("vv", "w")
        return norm_str

    def _extract_domains(self, text: str) -> List[str]:
        domains = []
        matches = URL_REGEX.findall(text)
        for match in matches:
            url = match if match.startswith(("http://", "https://")) else f"http://{match}"
            try:
                parsed = urllib.parse.urlparse(url)
                netloc = parsed.netloc.split(":")[0].lower()
                # Strip leading www.
                if netloc.startswith("www."):
                    netloc = netloc[4:]
                if netloc:
                    domains.append(netloc)
            except Exception:
                continue
        return domains

    def _is_whitelisted(self, domain: str, whitelist: List[str]) -> bool:
        for white in whitelist:
            white = white.lower().strip()
            if domain == white or domain.endswith("." + white):
                return True
        return False

    def _scan_domain(self, domain: str, protected_brands: List[str], threshold: float) -> Optional[Tuple[str, float]]:
        """Checks if domain resembles a protected brand using homoglyph mapping & Levenshtein distance."""
        clean_domain = self._normalize_homoglyphs(domain)
        parts = clean_domain.split(".")
        main_part = parts[0] if parts else clean_domain

        orig_parts = domain.lower().split(".")
        orig_main = orig_parts[0] if orig_parts else domain.lower()

        for brand in protected_brands:
            brand = brand.lower()
            # Case 1: Homoglyph or visual digraph spoof (e.g. discorcl -> discord)
            if orig_main != brand and main_part == brand:
                return (brand, 0.99)

            # Case 2: Brand name contained inside untrusted domain name (e.g. discord-gift, steam-claim)
            if brand in main_part and main_part != brand:
                return (brand, 0.95)

            # Case 3: Typosquatting edit distance
            ratio = Levenshtein.ratio(main_part, brand)
            if ratio >= threshold and main_part != brand:
                return (brand, ratio)

        return None

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

        cfg = bot_config.phishing_detector
        if not cfg.get("enabled", True):
            return

        whitelist = cfg.get("whitelisted_domains", [])
        protected_brands = cfg.get("protected_brands", ["discord", "nitro", "steamcommunity"])
        threshold = float(cfg.get("similarity_threshold", 0.82))

        domains = self._extract_domains(message.content)
        if not domains:
            return

        flagged_reason = None
        flagged_domain = None
        confidence = "HIGH (92%)"

        for domain in domains:
            if self._is_whitelisted(domain, whitelist):
                continue

            # Check for homoglyphs / brand spoofing
            spoof = self._scan_domain(domain, protected_brands, threshold)
            if spoof:
                brand, score = spoof
                flagged_reason = f"Phishing/Spoofed Domain impersonating '{brand}' (Domain: `{domain}`)"
                flagged_domain = domain
                confidence = f"HIGH ({int(score * 100)}%)"
                break

        if flagged_reason:
            await self._handle_phishing_incident(message, flagged_reason, flagged_domain, confidence)

    async def _handle_phishing_incident(self, message: discord.Message, reason: str, domain: str, confidence: str):
        member = message.author
        guild = message.guild
        dry_run = bot_config.dry_run

        action_taken = "[DRY RUN] Phishing Alert Sent to Mod Log" if dry_run else "Deleted Message & Applied 1-Hour Timeout"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered=reason,
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
                await member.timeout(timedelta(hours=1), reason=f"[Security Bot] {reason}")
            except Exception as e:
                logger.warning("Could not timeout %s: %s", member, e)

        # Dispatch alert
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"🛑 PHISHING LINK DETECTED {'[DRY RUN]' if dry_run else '[ENFORCED]'}",
            color=discord.Color.red(),
            description=f"A high-risk phishing or scam link was posted by {member.mention}."
        )
        embed.add_field(name="Offender", value=f"{member} (`{member.id}`)", inline=True)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="Confidence", value=f"`{confidence}`", inline=True)
        embed.add_field(name="Flagged Domain", value=f"`{domain}`", inline=False)

        # Redact raw URL preview
        preview = (message.content[:150] + "...") if len(message.content) > 150 else message.content
        embed.add_field(name="Message Snippet", value=f"```{preview}```", inline=False)
        embed.add_field(
            name="Recommended Action",
            value="Confirm the domain is a known scam. If malicious, use the **Ban Account** button below.",
            inline=False
        )
        embed.set_footer(text=f"Incident #{incident_id} • Status: {'Requires Review' if dry_run else 'Auto-Action Applied'}")

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
    await bot.add_cog(LinkFilter(bot))

"""Anti-Webhook Hijacking and Rogue Webhook Guard Cog.
Neutralizes leaked or compromised webhooks posting unauthorized @everyone or phishing URLs.
"""
import re
import logging
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.webhook_guard")

URL_REGEX = re.compile(r'(?:https?://|www\.)[^\s<>"\'`]+', re.IGNORECASE)

class WebhookGuard(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        # Only inspect messages created by Webhooks
        if not message.guild or not message.webhook_id:
            return

        guild = message.guild
        channel = message.channel

        cfg = bot_config.raw_data.get("webhook_guard", {})
        if not cfg.get("enabled", True):
            return

        # Check for unauthorized mass pings from webhooks
        is_mass_ping = message.mention_everyone or ("@everyone" in message.content or "@here" in message.content)
        
        # Check if webhook is posting scam / phishing lures
        content_lower = message.content.lower()
        is_scam_lure = any(word in content_lower for word in ["free nitro", "steam gift", "airdrop", "crypto giveaway"])

        if is_mass_ping or is_scam_lure:
            await self._neutralize_webhook(message, is_mass_ping, is_scam_lure)

    async def _neutralize_webhook(self, message: discord.Message, is_mass_ping: bool, is_scam_lure: bool):
        guild = message.guild
        channel = message.channel
        webhook_id = message.webhook_id
        dry_run = bot_config.dry_run

        reason = "Unauthorized @everyone ping" if is_mass_ping else "Scam / Phishing lure payload"
        action_text = "[DRY RUN] Webhook Hijack Alert Dispatched" if dry_run else "Deleted Message & Permanently Deleted Compromised Webhook"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=webhook_id,
            username=f"Webhook: {message.author.name}",
            rule_triggered=f"Webhook Hijack: {reason}",
            confidence="CRITICAL (100% Malicious Webhook Activity)",
            raw_evidence=message.content,
            action_taken=action_text
        )

        if not dry_run:
            # 1. Delete the malicious webhook message
            try:
                await message.delete()
            except Exception:
                pass

            # 2. Delete the webhook URL itself to revoke attacker's access permanently
            try:
                webhooks = await channel.webhooks()
                for wh in webhooks:
                    if wh.id == webhook_id:
                        await wh.delete(reason="[Security Bot] Compromised webhook neutralized")
                        logger.warning("Permanently deleted compromised webhook ID %d in #%s", webhook_id, channel.name)
                        break
            except Exception as e:
                logger.error("Failed to delete compromised webhook %d: %s", webhook_id, e)

        # Dispatch alert
        alert_ch_id = bot_config.alert_channel_id
        if alert_ch_id:
            alert_ch = self.bot.get_channel(alert_ch_id)
            if alert_ch:
                embed = discord.Embed(
                    title=f"🚨 HIJACKED WEBHOOK NEUTRALIZED {'[DRY RUN]' if dry_run else ''}",
                    color=discord.Color.red(),
                    description=(
                        f"A webhook posted in {channel.mention} attempted malicious activity.\n\n"
                        f"**Webhook Name:** `{message.author.name}`\n"
                        f"**Webhook ID:** `{webhook_id}`\n"
                        f"**Violation:** `{reason}`\n"
                        f"**Action:** `{action_text}`"
                    )
                )
                preview = (message.content[:150] + "...") if len(message.content) > 150 else message.content
                embed.add_field(name="Payload Snippet", value=f"```{preview}```", inline=False)
                embed.add_field(
                    name="Security Notice",
                    value="The webhook credentials were likely leaked or scraped from a public repository. The webhook has been terminated.",
                    inline=False
                )
                embed.set_footer(text=f"Incident #{incident_id} • Antigravity Webhook Shield")
                await alert_ch.send(content="@everyone" if not dry_run else None, embed=embed)

async def setup(bot: commands.Bot):
    await bot.add_cog(WebhookGuard(bot))

"""Join Raid Detector Cog.
Detects burst joins, waves of new/compromised accounts, and dispatches actionable moderator cards.
"""
import time
import logging
from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Deque, Tuple, List
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

logger = logging.getLogger("security_bot.raid_detector")

class RaidAlertView(discord.ui.View):
    """Action buttons tailored for server-wide raid events."""
    def __init__(self, incident_id: int, guild: discord.Guild, recent_member_ids: List[int]):
        super().__init__(timeout=86400)
        self.incident_id = incident_id
        self.guild = guild
        self.recent_member_ids = recent_member_ids

    def _is_mod(self, user: discord.Member) -> bool:
        return (
            user.guild_permissions.administrator or
            user.guild_permissions.moderate_members or
            user.guild.owner_id == user.id
        )

    @discord.ui.button(label="Activate Lockdown (15m)", style=discord.ButtonStyle.danger, emoji="🔒")
    async def lockdown_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        lockdown_cog = interaction.client.get_cog("ServerLockdown")
        if not lockdown_cog:
            await interaction.response.send_message("❌ Lockdown cog not available.", ephemeral=True)
            return

        success, msg = await lockdown_cog.apply_lockdown(interaction.guild, duration_minutes=15, reason="Join Raid Defense")
        if success:
            button.disabled = True
            button.label = "Lockdown Active (15m)"
            await interaction.message.edit(view=self)
            await interaction.response.send_message(f"🔒 {msg} Activated by {interaction.user.mention}.", ephemeral=False)
        else:
            await interaction.response.send_message(f"❌ Failed to activate lockdown: {msg}", ephemeral=True)

    @discord.ui.button(label="Timeout All Raid Accounts (10m)", style=discord.ButtonStyle.primary, emoji="⏱️")
    async def timeout_raid_members(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        count = 0
        for uid in self.recent_member_ids:
            mem = self.guild.get_member(uid)
            if mem and not mem.bot and not bot_config.is_bypassed(self.guild, mem):
                try:
                    await mem.timeout(timedelta(minutes=10), reason=f"Mass raid containment by {interaction.user}")
                    count += 1
                except Exception:
                    pass

        button.disabled = True
        button.label = f"Timed Out {count} Accounts"
        await interaction.message.edit(view=self)
        await interaction.followup.send(f"⏱️ Timed out {count} accounts involved in the raid wave.", ephemeral=True)

    @discord.ui.button(label="Dismiss Alert", style=discord.ButtonStyle.secondary, emoji="🛡️")
    async def dismiss_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await db.update_incident_status(self.incident_id, "DISMISSED", interaction.user.id)
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)
        await interaction.response.send_message(f"✅ Raid alert #{self.incident_id} dismissed by {interaction.user.mention}.", ephemeral=True)


class RaidDetector(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # Rolling deque storing (timestamp, member_id, created_at)
        self.join_history: Deque[Tuple[float, int, datetime]] = deque()
        self.last_alert_time: float = 0.0
        self.alert_cooldown_seconds: float = 45.0  # Avoid alert flooding during large raids

    def _prune_history(self, window_seconds: int) -> None:
        now = time.time()
        while self.join_history and (now - self.join_history[0][0]) > window_seconds:
            self.join_history.popleft()

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if member.bot:
            return

        cfg = bot_config.raid_detector
        if not cfg.get("enabled", True):
            return

        window_secs = int(cfg.get("window_seconds", 10))
        join_threshold = int(cfg.get("join_threshold", 5))
        new_account_age_hours = int(cfg.get("new_account_age_hours", 24))
        new_account_threshold = int(cfg.get("new_account_threshold", 3))

        now = time.time()
        self._prune_history(window_secs)
        self.join_history.append((now, member.id, member.created_at))

        recent_joins = list(self.join_history)
        total_joins = len(recent_joins)

        # Check account age of recent joins
        now_utc = datetime.now(timezone.utc)
        new_accounts = [
            uid for (t, uid, created_at) in recent_joins
            if (now_utc - created_at).total_seconds() < (new_account_age_hours * 3600)
        ]

        # Trigger condition: high join velocity OR wave of new accounts
        is_raid_velocity = total_joins >= join_threshold
        is_new_account_wave = len(new_accounts) >= new_account_threshold

        if (is_raid_velocity or is_new_account_wave) and (now - self.last_alert_time > self.alert_cooldown_seconds):
            self.last_alert_time = now
            confidence = "HIGH (95%)" if (is_raid_velocity and is_new_account_wave) else "MEDIUM (75%)"
            recent_ids = [uid for (_, uid, _) in recent_joins]

            await self._trigger_raid_alert(
                guild=member.guild,
                total_joins=total_joins,
                window_secs=window_secs,
                new_account_count=len(new_accounts),
                recent_member_ids=recent_ids,
                confidence=confidence,
                dry_run=bot_config.dry_run
            )

    async def _trigger_raid_alert(
        self,
        guild: discord.Guild,
        total_joins: int,
        window_secs: int,
        new_account_count: int,
        recent_member_ids: List[int],
        confidence: str,
        dry_run: bool
    ):
        evidence_str = f"{total_joins} joins in {window_secs}s ({new_account_count} new accounts <24h old)"
        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=recent_member_ids[-1] if recent_member_ids else 0,
            username=f"Raid Wave ({total_joins} accounts)",
            rule_triggered="Anti-Raid: Join Burst",
            confidence=confidence,
            raw_evidence=evidence_str,
            action_taken="[DRY RUN] Raid Alert Dispatched with Action Buttons" if dry_run else "Raid Containment Triggered"
        )

        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            logger.warning("No ALERT_CHANNEL_ID set. Raid detected: %s", evidence_str)
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title="🚨 RAID SURGE DETECTED",
            description=(
                f"A sudden join burst has been detected on **{guild.name}**.\n"
                f"**Join Rate:** `{total_joins}` members in `{window_secs}s`\n"
                f"**Suspicious Accounts (<24h old):** `{new_account_count}`\n"
                f"**Confidence:** `{confidence}`\n"
                f"**Mode:** `{'DRY RUN (Simulated)' if dry_run else 'ACTIVE ENFORCEMENT'}`"
            ),
            color=discord.Color.red() if confidence.startswith("HIGH") else discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )

        # List recent join IDs
        mentions_str = " ".join([f"<@{uid}>" for uid in recent_member_ids[:10]])
        if len(recent_member_ids) > 10:
            mentions_str += f" *(and {len(recent_member_ids) - 10} more)*"

        embed.add_field(name="Recent Joining Accounts", value=mentions_str or "None", inline=False)
        embed.add_field(name="Recommended Action", value="Activate a 15-minute lockdown or timeout recent accounts if unfamiliar.", inline=False)
        embed.set_footer(text=f"Incident #{incident_id} • Antigravity Security Suite")

        view = RaidAlertView(incident_id=incident_id, guild=guild, recent_member_ids=recent_member_ids)
        await alert_channel.send(content="@here" if not dry_run else None, embed=embed, view=view)

async def setup(bot: commands.Bot):
    await bot.add_cog(RaidDetector(bot))

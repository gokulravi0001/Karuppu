"""Voice Channel Protection Cog.
Protects all voice channels 24/7 simultaneously across the server WITHOUT needing the bot to join the voice room:
1. VC Hopping / Notification Chime Spam: Stops rapid channel switching (> 5 switches in 10s).
2. Mic Glitch & Audio Popping Spam: Stops rapid mute/unmute/deafen macros (>= 8 toggles in 4s).
3. Voice Channel Raid Surges: Detects coordinated raid waves flooding into voice channels.
"""
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Deque, Dict, Tuple, Optional, List
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.voice_protection")

class VoiceAlertView(discord.ui.View):
    """Moderator actions for Voice Channel security incidents."""
    def __init__(self, incident_id: int, guild: discord.Guild, target_user_id: int):
        super().__init__(timeout=86400)
        self.incident_id = incident_id
        self.guild = guild
        self.target_user_id = target_user_id

    def _is_mod(self, user: discord.Member) -> bool:
        return (
            user.guild_permissions.moderate_members or
            user.guild_permissions.mute_members or
            user.guild_permissions.administrator or
            user.guild.owner_id == user.id
        )

    @discord.ui.button(label="Unmute / Clear Mute", style=discord.ButtonStyle.success, emoji="🔊")
    async def unmute_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        member = self.guild.get_member(self.target_user_id)
        if not member or not member.voice:
            await interaction.response.send_message("❌ Member is not currently in a voice channel.", ephemeral=True)
            return

        try:
            await member.edit(mute=False, reason=f"Voice protection unmuted by {interaction.user}")
            button.disabled = True
            button.label = "Unmuted"
            await interaction.message.edit(view=self)
            await interaction.response.send_message(f"🔊 Server unmuted {member.mention}.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Failed to unmute: {e}", ephemeral=True)

    @discord.ui.button(label="Disconnect from VC", style=discord.ButtonStyle.danger, emoji="🔌")
    async def disconnect_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        member = self.guild.get_member(self.target_user_id)
        if not member or not member.voice:
            await interaction.response.send_message("❌ Member is not currently in a voice channel.", ephemeral=True)
            return

        try:
            await member.move_to(None, reason=f"Disconnected by {interaction.user}")
            button.disabled = True
            button.label = "Disconnected"
            await interaction.message.edit(view=self)
            await interaction.response.send_message(f"🔌 Disconnected {member.mention} from voice.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Failed to disconnect member: {e}", ephemeral=True)

    @discord.ui.button(label="Timeout (10m)", style=discord.ButtonStyle.primary, emoji="⏱️")
    async def timeout_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        member = self.guild.get_member(self.target_user_id)
        if not member:
            await interaction.response.send_message("❌ Member not found.", ephemeral=True)
            return

        try:
            await member.timeout(timedelta(minutes=10), reason=f"VC security incident by {interaction.user}")
            button.disabled = True
            button.label = "Timed Out (10m)"
            await interaction.message.edit(view=self)
            await interaction.response.send_message(f"⏱️ Timed out {member.mention} for 10 minutes.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Failed to timeout: {e}", ephemeral=True)

    @discord.ui.button(label="Dismiss", style=discord.ButtonStyle.secondary, emoji="🛡️")
    async def dismiss_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await db.update_incident_status(self.incident_id, "DISMISSED", interaction.user.id)
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)
        await interaction.response.send_message(f"✅ Alert #{self.incident_id} dismissed by {interaction.user.mention}.", ephemeral=True)


class VoiceRaidAlertView(discord.ui.View):
    """Actions for Voice Channel mass join raid surges."""
    def __init__(self, incident_id: int, guild: discord.Guild, candidate_ids: List[int], channel_id: int):
        super().__init__(timeout=86400)
        self.incident_id = incident_id
        self.guild = guild
        self.candidate_ids = candidate_ids
        self.channel_id = channel_id

    def _is_mod(self, user: discord.Member) -> bool:
        return (
            user.guild_permissions.moderate_members or
            user.guild_permissions.administrator or
            user.guild.owner_id == user.id
        )

    @discord.ui.button(label="Disconnect All Raid Accounts", style=discord.ButtonStyle.danger, emoji="⚠️")
    async def disconnect_all_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        disconnected_count = 0
        for uid in self.candidate_ids:
            mem = self.guild.get_member(uid)
            if mem and mem.voice:
                try:
                    await mem.move_to(None, reason=f"VC Raid purge confirmed by {interaction.user}")
                    disconnected_count += 1
                except Exception:
                    pass

        button.disabled = True
        button.label = f"Disconnected ({disconnected_count})"
        await interaction.message.edit(view=self)
        await interaction.response.send_message(f"🧹 Disconnected **{disconnected_count}** accounts from voice.", ephemeral=True)

    @discord.ui.button(label="Dismiss", style=discord.ButtonStyle.secondary, emoji="🛡️")
    async def dismiss_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        await db.update_incident_status(self.incident_id, "DISMISSED", interaction.user.id)
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)
        await interaction.response.send_message(f"✅ Voice raid alert #{self.incident_id} dismissed.", ephemeral=True)


class VoiceProtection(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # user_id -> deque of timestamps for VC joins/switches
        self.user_vc_events: Dict[int, Deque[float]] = defaultdict(deque)
        # user_id -> deque of timestamps for rapid mic/deaf toggles (audio glitch spam)
        self.user_mic_toggles: Dict[int, Deque[float]] = defaultdict(deque)
        # channel_id -> deque of (timestamp, user_id) for VC raid surges
        self.vc_channel_joins: Dict[int, Deque[Tuple[float, int]]] = defaultdict(deque)

    def _check_vc_hopping(self, user_id: int, max_switches: int, window_secs: int) -> bool:
        now = time.time()
        events = self.user_vc_events[user_id]
        events.append(now)

        while events and (now - events[0]) > window_secs:
            events.popleft()

        return len(events) >= max_switches

    def _check_mic_glitch_spam(self, user_id: int, max_toggles: int, window_secs: int) -> bool:
        now = time.time()
        events = self.user_mic_toggles[user_id]
        events.append(now)

        while events and (now - events[0]) > window_secs:
            events.popleft()

        return len(events) >= max_toggles

    def _check_vc_raid_surge(self, channel_id: int, user_id: int, join_threshold: int, window_secs: int) -> List[int]:
        now = time.time()
        joins = self.vc_channel_joins[channel_id]
        joins.append((now, user_id))

        while joins and (now - joins[0][0]) > window_secs:
            joins.popleft()

        if len(joins) >= join_threshold:
            # Return list of recent joiner IDs
            return [uid for _, uid in joins]
        return []

    @commands.Cog.listener()
    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        if member.bot or not member.guild:
            return

        guild = member.guild
        vc_channel = after.channel or before.channel

        # OWNER-EXCLUSIVE BYPASS
        if bot_config.is_bypassed(guild, member, vc_channel):
            return

        voice_cfg = bot_config.raw_data.get("voice_protection", {})
        if not voice_cfg.get("enabled", True):
            return

        # 1. VC HOPPING / NOTIFICATION CHIME SPAM CHECK
        hopping_cfg = voice_cfg.get("vc_hopping", {})
        if hopping_cfg.get("enabled", True):
            if before.channel != after.channel:
                max_switches = int(hopping_cfg.get("max_switches", 5))
                window_secs = int(hopping_cfg.get("window_seconds", 10))
                if self._check_vc_hopping(member.id, max_switches, window_secs):
                    await self._handle_vc_hopping_incident(member, vc_channel, max_switches, window_secs)
                    return

        # 2. RAPID MIC / DEAFEN GLITCH SPAM (Macro Popping Sounds)
        glitch_cfg = voice_cfg.get("mic_glitch_spam", {})
        if glitch_cfg.get("enabled", True) and after.channel:
            # Detect rapid toggle of self_mute or self_deaf while inside VC
            mute_changed = (before.self_mute != after.self_mute)
            deaf_changed = (before.self_deaf != after.self_deaf)
            if mute_changed or deaf_changed:
                max_toggles = int(glitch_cfg.get("max_toggles", 8))
                window_secs = int(glitch_cfg.get("window_seconds", 4))
                if self._check_mic_glitch_spam(member.id, max_toggles, window_secs):
                    await self._handle_mic_glitch_incident(member, after.channel, max_toggles, window_secs)
                    return

        # 3. VOICE CHANNEL RAID SURGE (Mass Joins into single VC)
        surge_cfg = voice_cfg.get("vc_raid_surge", {})
        if surge_cfg.get("enabled", True) and after.channel and before.channel != after.channel:
            join_threshold = int(surge_cfg.get("join_threshold", 4))
            window_secs = int(surge_cfg.get("window_seconds", 8))
            recent_uids = self._check_vc_raid_surge(after.channel.id, member.id, join_threshold, window_secs)
            if recent_uids:
                await self._handle_vc_raid_surge_incident(member.guild, after.channel, recent_uids, window_secs)

    async def _handle_vc_hopping_incident(
        self,
        member: discord.Member,
        vc_channel: Optional[discord.VoiceChannel],
        max_switches: int,
        window_secs: int
    ):
        guild = member.guild
        dry_run = bot_config.dry_run
        timeout_seconds = int(bot_config.raw_data.get("voice_protection", {}).get("vc_hopping", {}).get("auto_timeout_seconds", 300))
        action_text = f"[DRY RUN] Would disconnect & apply {timeout_seconds // 60}m timeout" if dry_run else f"Disconnected from VC & applied {timeout_seconds // 60}m timeout"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered="Voice Protection: Rapid VC Hopping / Sound Spam",
            confidence="HIGH (95%)",
            raw_evidence=f"{max_switches} voice transitions in {window_secs}s",
            action_taken=action_text
        )

        if not dry_run:
            try:
                if member.voice:
                    await member.move_to(None, reason="VC Hopping Sound Spam")
                await member.timeout(timedelta(seconds=timeout_seconds), reason="VC Hopping / Disconnect Chime Spam")
            except Exception as e:
                logger.warning("Error enforcing VC hopping action on %s: %s", member, e)

        await self._dispatch_voice_alert(
            member=member,
            channel=vc_channel,
            incident_id=incident_id,
            title=f"🔊 VC Connect / Hopping Spam {'[DRY RUN]' if dry_run else '[DISCONNECTED]'}",
            description=f"{member.mention} rapidly switched or joined voice channels `{max_switches}` times in `{window_secs}s` (Notification Chime Spam).",
            recommendation="Member was disconnected and timed out for 5m. Protects other members from constant chime sounds.",
            dry_run=dry_run
        )

    async def _handle_mic_glitch_incident(
        self,
        member: discord.Member,
        vc_channel: discord.VoiceChannel,
        max_toggles: int,
        window_secs: int
    ):
        guild = member.guild
        dry_run = bot_config.dry_run
        timeout_seconds = int(bot_config.raw_data.get("voice_protection", {}).get("mic_glitch_spam", {}).get("auto_timeout_seconds", 180))
        action_text = f"[DRY RUN] Would Server-Mute & apply {timeout_seconds // 60}m timeout" if dry_run else f"Server-Muted & applied {timeout_seconds // 60}m timeout"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered="Voice Protection: Rapid Mic / Deafen Glitch Spam",
            confidence="HIGH (98%)",
            raw_evidence=f"{max_toggles} mic/deaf toggles in {window_secs}s in #{vc_channel.name}",
            action_taken=action_text
        )

        if not dry_run:
            try:
                if member.voice:
                    await member.edit(mute=True, reason="Rapid Mic Toggle / Audio Popping Spam")
                await member.timeout(timedelta(seconds=timeout_seconds), reason="Rapid Mic Toggle / Audio Popping Spam")
            except Exception as e:
                logger.warning("Error enforcing mic glitch action on %s: %s", member, e)

        await self._dispatch_voice_alert(
            member=member,
            channel=vc_channel,
            incident_id=incident_id,
            title=f"🔇 Mic / Audio Glitch Spam {'[DRY RUN]' if dry_run else '[SERVER MUTED]'}",
            description=f"{member.mention} rapidly toggled microphone/deafen `{max_toggles}` times in `{window_secs}s` in {vc_channel.mention} (Audio Glitch / Popping Spam).",
            recommendation="Member was server-muted and timed out for 3m to protect everyone's ears from audio macro glitching.",
            dry_run=dry_run
        )

    async def _handle_vc_raid_surge_incident(
        self,
        guild: discord.Guild,
        vc_channel: discord.VoiceChannel,
        recent_uids: List[int],
        window_secs: int
    ):
        dry_run = bot_config.dry_run
        unique_uids = list(set(recent_uids))
        now = datetime.now(timezone.utc)

        # Check for new accounts (< 24h) or members with no roles
        suspicious_members = []
        for uid in unique_uids:
            mem = guild.get_member(uid)
            if not mem or mem.bot:
                continue
            account_age_hours = (now - mem.created_at).total_seconds() / 3600
            if account_age_hours < 24 or len(mem.roles) <= 1:
                suspicious_members.append(mem)

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=0,
            username=f"VC Raid Surge ({len(unique_uids)} joins)",
            rule_triggered="Voice Protection: VC Mass Join Surge",
            confidence="HIGH",
            raw_evidence=f"{len(unique_uids)} joins in #{vc_channel.name} within {window_secs}s ({len(suspicious_members)} suspicious)",
            action_taken=f"{'Logged alert only' if dry_run else 'Auto-disconnected suspicious accounts'}"
        )

        if not dry_run and suspicious_members:
            for mem in suspicious_members:
                try:
                    if mem.voice:
                        await mem.move_to(None, reason="VC Raid Surge Containment")
                except Exception:
                    pass

        # Dispatch alert card
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=f"🚨 Voice Channel Raid Surge Detected in #{vc_channel.name}",
            color=discord.Color.red(),
            description=(
                f"**{len(unique_uids)} accounts** flooded into {vc_channel.mention} in under `{window_secs}s`!\n\n"
                f"• **Suspicious Accounts (<24h age or 0 roles):** `{len(suspicious_members)}`\n"
                f"• **Sample Users:** {', '.join([m.mention for m in suspicious_members[:5]]) if suspicious_members else 'None'}\n\n"
                f"Protecting active voice members from channel disruption."
            )
        )
        embed.set_footer(text=f"Incident #{incident_id} • Antigravity Voice Defense")
        view = VoiceRaidAlertView(incident_id=incident_id, guild=guild, candidate_ids=unique_uids, channel_id=vc_channel.id)
        await alert_channel.send(embed=embed, view=view)

    async def _dispatch_voice_alert(
        self,
        member: discord.Member,
        channel: Optional[discord.VoiceChannel],
        incident_id: int,
        title: str,
        description: str,
        recommendation: str,
        dry_run: bool
    ):
        alert_ch_id = bot_config.alert_channel_id
        if not alert_ch_id:
            return

        alert_channel = self.bot.get_channel(alert_ch_id)
        if not alert_channel:
            return

        embed = discord.Embed(
            title=title,
            color=discord.Color.gold() if dry_run else discord.Color.orange(),
            description=description
        )
        embed.add_field(name="Member", value=f"{member.mention} (`{member.id}`)", inline=True)
        if channel:
            embed.add_field(name="Voice Channel", value=f"#{channel.name} (`{channel.id}`)", inline=True)
        embed.add_field(name="Mode", value="`DRY RUN (Alert Only)`" if dry_run else "`ACTIVE ENFORCEMENT`", inline=True)
        embed.add_field(name="Recommended Action", value=recommendation, inline=False)
        embed.set_footer(text=f"Incident #{incident_id} • Antigravity Voice Defense")

        view = VoiceAlertView(incident_id=incident_id, guild=member.guild, target_user_id=member.id)
        await alert_channel.send(embed=embed, view=view)

async def setup(bot: commands.Bot):
    await bot.add_cog(VoiceProtection(bot))

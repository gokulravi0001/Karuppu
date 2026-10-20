"""Voice Channel & Microphone Protection Cog.
Protects against mic spam, unauthorized mic usage by low-level/raid accounts, and rapid VC connect/disconnect hopping.
"""
import time
import logging
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, Tuple, Optional
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db
from src.cogs.moderation_view import SecurityAlertView

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

    @discord.ui.button(label="Unmute Member", style=discord.ButtonStyle.success, emoji="🔊")
    async def unmute_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        member = self.guild.get_member(self.target_user_id)
        if not member or not member.voice:
            await interaction.response.send_message("❌ Member is not currently in a voice channel.", ephemeral=True)
            return

        try:
            await member.edit(mute=False, reason=f"Server unmuted by {interaction.user}")
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


class VoiceProtection(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # user_id -> deque of timestamps for VC joins/switches
        self.user_vc_events: Dict[int, Deque[float]] = defaultdict(deque)

    def _check_vc_hopping(self, user_id: int, max_switches: int, window_secs: int) -> bool:
        now = time.time()
        events = self.user_vc_events[user_id]
        events.append(now)

        # Prune events older than window
        while events and (now - events[0]) > window_secs:
            events.popleft()

        return len(events) >= max_switches

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

        # 1. VC HOPPING / CONNECT-DISCONNECT SOUND SPAM CHECK
        hopping_cfg = voice_cfg.get("vc_hopping", {})
        if hopping_cfg.get("enabled", True):
            # Check if user changed channels or newly joined
            if before.channel != after.channel:
                max_switches = int(hopping_cfg.get("max_switches", 5))
                window_secs = int(hopping_cfg.get("window_seconds", 10))
                if self._check_vc_hopping(member.id, max_switches, window_secs):
                    await self._handle_vc_hopping_incident(member, after.channel or before.channel, max_switches, window_secs)
                    return

        # 2. MICROPHONE / SPEAKING GATE (Progressive Trust in VC)
        mic_cfg = voice_cfg.get("mic_gate", {})
        if mic_cfg.get("enabled", True) and after.channel:
            # Check if user is in a voice channel and has their microphone UNMUTED
            # (i.e. not self-muted and not server-muted)
            is_unmuted = not after.self_mute and not after.mute
            
            # Did they just unmute or join unmuted?
            was_unmuted = not before.self_mute and not before.mute if before.channel else False

            if is_unmuted:
                required_role = mic_cfg.get("required_role", "Level 3")
                if not bot_config.has_required_role(member, required_role):
                    await self._handle_mic_violation(member, after.channel, str(required_role), mic_cfg)

    async def _handle_mic_violation(
        self,
        member: discord.Member,
        vc_channel: discord.VoiceChannel,
        required_role: str,
        mic_cfg: dict
    ):
        guild = member.guild
        dry_run = bot_config.dry_run
        reminder_template = mic_cfg.get(
            "reminder_text",
            "🎙️ **Microphone access in voice channels unlocks at {required_role}!** You can still listen in. Keep chatting in text channels to level up."
        )
        formatted_reminder = reminder_template.format(required_role=required_role, user=member.mention)
        action_text = "[DRY RUN] Would Server-Mute mic & send educational note" if dry_run else "Server-Muted member until required level role is reached"

        incident_id = await db.log_incident(
            guild_id=guild.id,
            user_id=member.id,
            username=str(member),
            rule_triggered="Voice Protection: Mic Gated (Level Role Required)",
            confidence="HIGH (100% Deterministic Voice State)",
            raw_evidence=f"Unmuted microphone in #{vc_channel.name} without role '{required_role}'",
            action_taken=action_text
        )

        if not dry_run:
            # Active enforcement: Server-mute member's microphone
            try:
                await member.edit(mute=True, reason=f"[Voice Security] Mic access requires {required_role}")
            except discord.Forbidden:
                logger.warning("Bot lacks 'Mute Members' permission to server-mute %s in %s", member, vc_channel.name)
            except Exception as e:
                logger.error("Error muting member %s: %s", member, e)

            # Friendly, non-invasive DM notification
            if mic_cfg.get("notify_user", True):
                try:
                    await member.send(f"Hey {member.name},\n{formatted_reminder}")
                except Exception:
                    pass  # Ignore if user DMs are closed

        # Dispatch alert card to mod log
        await self._dispatch_voice_alert(
            member=member,
            channel=vc_channel,
            incident_id=incident_id,
            title=f"🎙️ VC Mic Access Violation {'[DRY RUN]' if dry_run else '[MUTED]'}",
            description=f"{member.mention} attempted to use microphone in {vc_channel.mention} without having **{required_role}**.",
            recommendation=f"Member was server-muted. When they reach **{required_role}**, they will be able to speak freely.",
            dry_run=dry_run
        )

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

        # Dispatch alert card
        await self._dispatch_voice_alert(
            member=member,
            channel=vc_channel,
            incident_id=incident_id,
            title=f"🔊 VC Connect / Hopping Spam {'[DRY RUN]' if dry_run else '[DISCONNECTED]'}",
            description=f"{member.mention} rapidly switched or joined voice channels `{max_switches}` times in `{window_secs}s` (Notification Chime Spam).",
            recommendation="Member was disconnected and timed out for 5m. Review if action was malicious or a connectivity glitch.",
            dry_run=dry_run
        )

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

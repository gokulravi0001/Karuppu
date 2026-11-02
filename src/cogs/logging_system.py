"""Comprehensive Audit & Logging Suite Cog.
Logs Chat (edits/deletions), Voice (joins/leaves/switches), Members (joins/leaves),
and Moderation Actions (who banned/kicked/timed out whom + reasons) into dedicated channels.
"""
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Union
import discord
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.logging_system")

# Discord Default Soundboard Sounds (built-in sound IDs)
DEFAULT_SOUNDBOARD_SOUNDS: dict[int, tuple[str, str]] = {
    1: ("🦆", "Quack"),
    2: ("📢", "Airhorn"),
    3: ("🦗", "Cricket"),
    4: ("👏", "Golf Clap"),
    5: ("🎺", "Sad Horn"),
    6: ("🥁", "Ba-Dum Tss"),
}

class LoggingSystem(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _get_target_channel(self, guild: discord.Guild, category: str) -> Optional[discord.TextChannel]:
        """Resolves the dedicated log channel for a category in a guild."""
        ch_id = bot_config.get_log_channel_id(guild.id, category)
        if ch_id:
            ch = guild.get_channel(ch_id)
            if isinstance(ch, discord.TextChannel):
                return ch
        return None

    # ==========================================
    # 1. CHAT LOGS (Message Edits & Deletions)
    # ==========================================
    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message):
        if not message.guild or message.author.bot:
            return

        log_channel = self._get_target_channel(message.guild, "message") or self._get_target_channel(message.guild, "chat")
        if not log_channel:
            return

        embed = discord.Embed(
            title=f"🗑️ Message Deleted in #{message.channel.name}",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_author(name=str(message.author), icon_url=message.author.display_avatar.url)
        embed.add_field(name="Author", value=f"{message.author.mention} (`{message.author.id}`)", inline=True)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)

        content_preview = message.content or "*[No text content]*"
        if len(content_preview) > 1024:
            content_preview = content_preview[:1020] + "..."
        embed.add_field(name="Deleted Content", value=content_preview, inline=False)

        if message.attachments:
            filenames = ", ".join([f"`{a.filename}`" for a in message.attachments])
            embed.add_field(name="Attachments", value=filenames, inline=False)

        embed.set_footer(text=f"Message ID: {message.id}")
        try:
            await log_channel.send(embed=embed)
        except Exception as e:
            logger.debug("Failed posting delete log: %s", e)

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        if not before.guild or before.author.bot:
            return
        # Ignore embed preview updates where text content didn't change
        if before.content == after.content:
            return

        log_channel = self._get_target_channel(before.guild, "message") or self._get_target_channel(before.guild, "chat")
        if not log_channel:
            return

        embed = discord.Embed(
            title=f"✏️ Message Edited in #{after.channel.name}",
            color=discord.Color.gold(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_author(name=str(after.author), icon_url=after.author.display_avatar.url)
        embed.add_field(name="Author", value=f"{after.author.mention} (`{after.author.id}`)", inline=True)
        embed.add_field(name="Channel", value=after.channel.mention, inline=True)
        embed.add_field(name="Jump to Message", value=f"[Click here to view]({after.jump_url})", inline=True)

        before_text = (before.content[:1020] + "...") if len(before.content) > 1024 else (before.content or "*[Empty]*")
        after_text = (after.content[:1020] + "...") if len(after.content) > 1024 else (after.content or "*[Empty]*")

        embed.add_field(name="Before", value=before_text, inline=False)
        embed.add_field(name="After", value=after_text, inline=False)
        embed.set_footer(text=f"Message ID: {after.id}")

        try:
            await log_channel.send(embed=embed)
        except Exception as e:
            logger.debug("Failed posting edit log: %s", e)

    # ==========================================
    # 2. VOICE CHANNEL LOGS (Joins, Leaves, Switches, Moves, Mutes/Deafens)
    # ==========================================
    async def _find_voice_moderator(
        self,
        guild: discord.Guild,
        action: discord.AuditLogAction,
        target_id: Optional[int] = None,
        max_age_seconds: float = 6.0
    ) -> Optional[Union[discord.Member, discord.User]]:
        """Looks up Discord audit logs to find which moderator triggered a voice state change."""
        if not guild.me.guild_permissions.view_audit_log:
            return None
        # Short sleep to allow Discord's audit log entry to register
        await asyncio.sleep(0.5)
        try:
            now_utc = datetime.now(timezone.utc)
            async for entry in guild.audit_logs(limit=5, action=action):
                time_diff = (now_utc - entry.created_at).total_seconds()
                if time_diff < 0 or time_diff > max_age_seconds:
                    continue
                if target_id is not None:
                    try:
                        entry_tid = getattr(entry.target, "id", getattr(entry, "_target_id", None))
                    except Exception:
                        entry_tid = getattr(entry, "_target_id", None)
                    if entry_tid == target_id:
                        return entry.user
                else:
                    return entry.user
        except Exception as e:
            logger.debug("Failed querying voice audit log for %s: %s", action, e)
        return None

    @commands.Cog.listener()
    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        if not member.guild:
            return

        guild = member.guild
        voice_log_channel = self._get_target_channel(guild, "voice")
        vc_state_log_channel = self._get_target_channel(guild, "vc_state")
        # If vc_state is not explicitly set, fall back to voice_log_channel or alert channel
        state_dest_channel = vc_state_log_channel or voice_log_channel or self.bot.get_channel(bot_config.get_alert_channel_id(guild.id))

        # Enforce active VC bans and timeouts (instantly disconnect punished users attempting to join VC)
        if after.channel is not None:
            block = bot_config.is_vc_blocked(guild.id, member.id)
            if not block:
                try:
                    block = await db.get_user_vc_punishment(guild.id, member.id)
                    if block:
                        bot_config.vc_punishments_cache[(guild.id, member.id)] = block
                except Exception:
                    pass

            if block:
                p_type = block.get("punishment_type", "restriction")
                reason = block.get("reason", "Voice channel moderation enforcement")

                # 1. Deny channel connect permission overwrite so Discord client blocks them
                try:
                    if guild.me.guild_permissions.manage_channels:
                        await after.channel.set_permissions(member, connect=False, speak=False, reason=f"VC {p_type.capitalize()} Enforcement")
                except Exception as e:
                    logger.debug("Failed setting connect=False overwrite for %s: %s", member.id, e)

                # 2. Server-mute and deafen immediately
                try:
                    if guild.me.guild_permissions.mute_members:
                        await member.edit(mute=True, deafen=True, reason=f"VC {p_type.capitalize()}: {reason}")
                except Exception:
                    pass

                # 3. Disconnect from voice
                try:
                    await member.move_to(None, reason=f"Active VC {p_type.capitalize()}: {reason}")
                    logger.info("Instantly disconnected VC-blocked member %s (%s) from #%s in %s", member, member.id, after.channel.name, guild.name)
                except discord.Forbidden:
                    logger.warning("Discord Forbidden: Cannot disconnect %s from VC because user has higher role/admin than bot in %s", member.id, guild.name)
                    # Send alert to mod log channel
                    alert_ch_id = bot_config.get_log_channel_id(guild.id, "mod") or bot_config.get_log_channel_id(guild.id, "voice") or bot_config.get_alert_channel_id(guild.id)
                    if alert_ch_id:
                        ch = guild.get_channel(alert_ch_id)
                        if isinstance(ch, discord.TextChannel):
                            embed = discord.Embed(
                                title="⚠️ VC Ban Enforcement Blocked by Discord Role Hierarchy",
                                color=discord.Color.red(),
                                description=(
                                    f"**Member:** {member.mention} (`{member.id}`)\n"
                                    f"**Active Punishment:** `{p_type.upper()}`\n"
                                    f"**Channel Joined:** {after.channel.mention}\n\n"
                                    f"❌ **Discord 403 Forbidden**: The bot cannot disconnect {member.mention} because their highest role (`{member.top_role.name}`) is equal to or higher than the bot's highest role (`{guild.me.top_role.name}`), or they have Administrator permissions.\n\n"
                                    f"👉 **To fix this**: Go to **Server Settings -> Roles**, and drag **Karuppu**'s role **ABOVE** other roles."
                                ),
                                timestamp=datetime.now(timezone.utc)
                            )
                            try:
                                await ch.send(embed=embed)
                            except Exception:
                                pass
                except Exception as e:
                    logger.error("Failed disconnecting VC-blocked member %s: %s", member.id, e)
                return

        embed = None
        now_ts = datetime.now(timezone.utc)

        # ----------------------------------------------------
        # A. VOICE MODERATION & STRUCTURAL LOGS (voice channel)
        # ----------------------------------------------------
        if voice_log_channel:
            # 1. Member Joined Voice Channel
            if before.channel is None and after.channel is not None:
                embed = discord.Embed(
                    title="🔊 Member Joined Voice Channel",
                    color=discord.Color.green(),
                    timestamp=now_ts
                )
                embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                embed.add_field(name="Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                embed.add_field(name="Voice Channel", value=f"#{after.channel.name} (`{after.channel.id}`)", inline=True)

            # 2. Member Left Voice Channel or Disconnected by Moderator
            elif before.channel is not None and after.channel is None:
                disconnector = await self._find_voice_moderator(
                    guild=guild,
                    action=discord.AuditLogAction.member_disconnect,
                    max_age_seconds=6.0
                )
                if disconnector:
                    embed = discord.Embed(
                        title="🔌 Member Disconnected by Moderator",
                        color=discord.Color.dark_red(),
                        timestamp=now_ts
                    )
                    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    embed.add_field(name="Target Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                    embed.add_field(name="Voice Channel", value=f"#{before.channel.name} (`{before.channel.id}`)", inline=True)
                    embed.add_field(name="Disconnected By", value=f"{disconnector.mention} (`{disconnector.id}`)", inline=False)
                else:
                    embed = discord.Embed(
                        title="🔇 Member Left Voice Channel",
                        color=discord.Color.red(),
                        timestamp=now_ts
                    )
                    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    embed.add_field(name="Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                    embed.add_field(name="Voice Channel", value=f"#{before.channel.name} (`{before.channel.id}`)", inline=True)
                    embed.add_field(name="Action By", value="Self (User left VC)", inline=True)

            # 3. Member Switched Channels or Moved by Moderator
            elif before.channel is not None and after.channel is not None and before.channel.id != after.channel.id:
                mover = await self._find_voice_moderator(
                    guild=guild,
                    action=discord.AuditLogAction.member_move,
                    max_age_seconds=6.0
                )
                if mover:
                    embed = discord.Embed(
                        title="🚚 Member Moved by Moderator",
                        color=discord.Color.gold(),
                        timestamp=now_ts
                    )
                    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    embed.add_field(name="Target Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                    embed.add_field(name="Moved By", value=f"{mover.mention} (`{mover.id}`)", inline=True)
                    embed.add_field(name="Previous Channel", value=f"#{before.channel.name}", inline=True)
                    embed.add_field(name="New Channel", value=f"#{after.channel.name}", inline=True)
                else:
                    embed = discord.Embed(
                        title="🔄 Member Switched Voice Channels",
                        color=discord.Color.blue(),
                        timestamp=now_ts
                    )
                    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    embed.add_field(name="Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                    embed.add_field(name="Previous Channel", value=f"#{before.channel.name}", inline=True)
                    embed.add_field(name="New Channel", value=f"#{after.channel.name}", inline=True)
                    embed.add_field(name="Action By", value="Self (User switched)", inline=True)

            # 4. Server Mute / Deafen Changes (Who Muted or Deafened Whom)
            elif before.mute != after.mute or before.deaf != after.deaf:
                state_text = []
                if before.mute != after.mute:
                    state_text.append(f"Server {'Muted' if after.mute else 'Unmuted'}")
                if before.deaf != after.deaf:
                    state_text.append(f"Server {'Deafened' if after.deaf else 'Undeafened'}")

                state_desc = ", ".join(state_text)
                action_moderator = await self._find_voice_moderator(
                    guild=guild,
                    action=discord.AuditLogAction.member_update,
                    target_id=member.id,
                    max_age_seconds=6.0
                )

                mod_display = (
                    f"{action_moderator.mention} (`{action_moderator.id}`)"
                    if action_moderator else "Unknown / Automated Bot"
                )

                embed = discord.Embed(
                    title=f"🎙️ Voice Moderation: {state_desc}",
                    color=discord.Color.purple() if (after.mute or after.deaf) else discord.Color.teal(),
                    timestamp=now_ts
                )
                embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                embed.add_field(name="Target Member", value=f"{member.mention} (`{member.id}`)", inline=True)
                embed.add_field(name="Action Taken", value=f"**{state_desc}**", inline=True)
                embed.add_field(name="Moderator", value=mod_display, inline=False)
                vc_target = after.channel or before.channel
                if vc_target:
                    embed.add_field(name="Voice Channel", value=f"#{vc_target.name} (`{vc_target.id}`)", inline=True)

            if embed:
                try:
                    await voice_log_channel.send(embed=embed)
                except Exception as e:
                    logger.debug("Failed posting voice log: %s", e)

        # ----------------------------------------------------
        # B. DETAILED VC STATE LOGS (vc_state channel, or voice log fallback)
        # ----------------------------------------------------
        if state_dest_channel:
            vc_target = after.channel or before.channel
            channel_name = f"#{vc_target.name} (`{vc_target.id}`)" if vc_target else "*Unknown Channel*"
            channel_mention = vc_target.mention if vc_target else channel_name

            # 1. Join / Leave / Switch events in dedicated vc_state channel (only if distinct from voice_log_channel)
            if vc_state_log_channel and (not voice_log_channel or vc_state_log_channel.id != voice_log_channel.id):
                if before.channel is None and after.channel is not None:
                    j_embed = discord.Embed(
                        title="🟢 Member Connected to Voice",
                        color=discord.Color.green(),
                        timestamp=now_ts
                    )
                    j_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    j_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                    j_embed.add_field(name="Voice Channel", value=f"{channel_mention} (`#{after.channel.name}`)", inline=True)

                    states = []
                    states.append("🔴 Self-Muted" if after.self_mute else "🟢 Mic Active")
                    if after.self_deaf:
                        states.append("🔇 Deafened")
                    if after.self_video:
                        states.append("📹 Camera ON")
                    if after.self_stream:
                        states.append("📺 Streaming")
                    j_embed.add_field(name="Initial VC Status", value=" • ".join(states), inline=False)
                    try:
                        await vc_state_log_channel.send(embed=j_embed)
                    except Exception as e:
                        logger.debug("Failed posting vc join log: %s", e)

                elif before.channel is not None and after.channel is None:
                    l_embed = discord.Embed(
                        title="🔴 Member Disconnected from Voice",
                        color=discord.Color.red(),
                        timestamp=now_ts
                    )
                    l_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    l_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                    l_embed.add_field(name="Voice Channel", value=f"#{before.channel.name} (`{before.channel.id}`)", inline=True)
                    try:
                        await vc_state_log_channel.send(embed=l_embed)
                    except Exception as e:
                        logger.debug("Failed posting vc leave log: %s", e)

                elif before.channel is not None and after.channel is not None and before.channel.id != after.channel.id:
                    sw_embed = discord.Embed(
                        title="🔄 Member Switched Voice Channel",
                        color=discord.Color.blue(),
                        timestamp=now_ts
                    )
                    sw_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                    sw_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                    sw_embed.add_field(name="Previous Channel", value=f"#{before.channel.name}", inline=True)
                    sw_embed.add_field(name="New Channel", value=f"{after.channel.mention} (`#{after.channel.name}`)", inline=True)
                    try:
                        await vc_state_log_channel.send(embed=sw_embed)
                    except Exception as e:
                        logger.debug("Failed posting vc switch log: %s", e)

            # 2. Camera / Video Turned ON or OFF
            if before.self_video != after.self_video:
                is_video = after.self_video
                v_embed = discord.Embed(
                    title="📹 Camera Turned ON" if is_video else "⬛ Camera Turned OFF",
                    color=discord.Color.green() if is_video else discord.Color.dark_grey(),
                    timestamp=now_ts
                )
                v_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                v_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                v_embed.add_field(name="Voice Channel", value=f"{channel_mention} (`#{vc_target.name}`)", inline=True)
                v_embed.add_field(
                    name="Camera State",
                    value="🟢 **Video Enabled (Camera Live)**" if is_video else "⚫ **Video Disabled (Camera Off)**",
                    inline=False
                )
                mic_state = "🔴 Muted" if (after.self_mute or after.mute) else "🟢 Unmuted"
                deaf_state = "🔇 Deafened" if (after.self_deaf or after.deaf) else "🔈 Listening"
                stream_state = "📺 Streaming" if after.self_stream else "None"
                v_embed.add_field(name="Mic Status", value=mic_state, inline=True)
                v_embed.add_field(name="Audio Status", value=deaf_state, inline=True)
                v_embed.add_field(name="Screenshare", value=stream_state, inline=True)
                try:
                    await state_dest_channel.send(embed=v_embed)
                except Exception as e:
                    logger.debug("Failed posting vc state video log: %s", e)

            # 3. Screen Share / Streaming Started or Stopped
            if before.self_stream != after.self_stream:
                is_stream = after.self_stream
                s_embed = discord.Embed(
                    title="📺 Screen Share Started" if is_stream else "⏹️ Screen Share Ended",
                    color=discord.Color.purple() if is_stream else discord.Color.dark_grey(),
                    timestamp=now_ts
                )
                s_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                s_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                s_embed.add_field(name="Voice Channel", value=f"{channel_mention} (`#{vc_target.name}`)", inline=True)
                s_embed.add_field(
                    name="Stream Status",
                    value="📡 **Live Broadcast / Screen Share Active**" if is_stream else "⚫ **Screen Sharing Stopped**",
                    inline=False
                )
                try:
                    await state_dest_channel.send(embed=s_embed)
                except Exception as e:
                    logger.debug("Failed posting vc state stream log: %s", e)

            # 4. Member Muted / Unmuted Themselves
            if before.self_mute != after.self_mute:
                is_muted = after.self_mute
                m_embed = discord.Embed(
                    title="🎙️ Member Self-Mute: MUTED" if is_muted else "🎙️ Member Self-Mute: UNMUTED",
                    color=discord.Color.red() if is_muted else discord.Color.green(),
                    timestamp=now_ts
                )
                m_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                m_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                m_embed.add_field(name="Voice Channel", value=f"{channel_mention} (`#{vc_target.name}`)", inline=True)
                m_embed.add_field(name="Microphone", value="🔴 **Muted Microphone (Self)**" if is_muted else "🟢 **Unmuted Microphone (Speaking)**", inline=False)
                try:
                    await state_dest_channel.send(embed=m_embed)
                except Exception as e:
                    logger.debug("Failed posting vc state mute log: %s", e)

            # 5. Member Deafened / Undeafened Themselves
            if before.self_deaf != after.self_deaf:
                is_deaf = after.self_deaf
                d_embed = discord.Embed(
                    title="🎧 Member Self-Deafen: DEAFENED" if is_deaf else "🎧 Member Self-Deafen: UNDEAFENED",
                    color=discord.Color.dark_red() if is_deaf else discord.Color.green(),
                    timestamp=now_ts
                )
                d_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                d_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                d_embed.add_field(name="Voice Channel", value=f"{channel_mention} (`#{vc_target.name}`)", inline=True)
                d_embed.add_field(name="Headphones", value="🔇 **Deafened Themselves (Audio Off)**" if is_deaf else "🔈 **Undeafened (Audio Restored)**", inline=False)
                try:
                    await state_dest_channel.send(embed=d_embed)
                except Exception as e:
                    logger.debug("Failed posting vc state deafen log: %s", e)

            # 6. Audio / Video Suppressed (Stage or Permission)
            if before.suppress != after.suppress:
                is_supp = after.suppress
                sp_embed = discord.Embed(
                    title="🔇 Member Voice/Video Suppressed",
                    color=discord.Color.orange() if is_supp else discord.Color.teal(),
                    timestamp=now_ts
                )
                sp_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
                sp_embed.add_field(name="Member", value=f"{member.mention} (`{member.name}` | `{member.id}`)", inline=True)
                sp_embed.add_field(name="Voice Channel", value=f"{channel_mention} (`#{vc_target.name}`)", inline=True)
                sp_embed.add_field(name="Suppression", value="🔇 **Suppressed by Stage / Moderator**" if is_supp else "🔊 **Suppression Removed**", inline=False)
                try:
                    await state_dest_channel.send(embed=sp_embed)
                except Exception as e:
                    logger.debug("Failed posting vc state suppress log: %s", e)

    # ==========================================
    # 2B. SOUNDBOARD & VOICE CHANNEL EFFECTS
    # ==========================================
    @commands.Cog.listener()
    async def on_voice_channel_effect(self, effect: discord.VoiceChannelEffect):
        channel = effect.channel
        guild = getattr(channel, "guild", None)
        if not guild:
            return

        logger.info(
            "Voice channel effect triggered in guild '%s' (#%s) by user: %s",
            guild.name,
            getattr(channel, 'name', 'Unknown Channel'),
            effect.user
        )

        # Prioritize dedicated vc_state log channel; fall back to voice log channel or alert channel
        log_channel = (
            self._get_target_channel(guild, "vc_state")
            or self._get_target_channel(guild, "voice")
            or self.bot.get_channel(bot_config.get_alert_channel_id(guild.id))
        )
        if not log_channel:
            logger.warning("No log channel available to dispatch soundboard effect in guild %s", guild.id)
            return

        user = effect.user
        user_mention = user.mention if user else "Unknown Member"
        user_id = user.id if user else "Unknown ID"
        user_name = str(user) if user else "Unknown User"
        avatar_url = user.display_avatar.url if (user and hasattr(user, "display_avatar")) else None

        now_ts = datetime.now(timezone.utc)
        embed = discord.Embed(
            title="🔊 Soundboard Audio Played",
            color=discord.Color.from_rgb(88, 101, 242),
            timestamp=now_ts
        )
        if avatar_url:
            embed.set_author(name=f"{user_name} played a sound", icon_url=avatar_url)

        embed.add_field(name="Member", value=f"{user_mention} (`{user_name}` | `{user_id}`)", inline=True)
        if channel:
            embed.add_field(name="Voice Channel", value=f"{channel.mention} (`#{channel.name}`)", inline=True)

        if effect.sound is not None:
            sound = effect.sound
            sound_id = getattr(sound, "id", None)
            sound_name = None
            sound_emoji = "🎵"
            source_tag = "Custom Server Sound"

            # 1. Check Discord Default Soundboard Sounds (1 to 6)
            if sound_id in DEFAULT_SOUNDBOARD_SOUNDS:
                emoji_str, default_name = DEFAULT_SOUNDBOARD_SOUNDS[sound_id]
                sound_name = default_name
                sound_emoji = emoji_str
                source_tag = "Discord Built-In Default"
            else:
                # 2. Check current guild's soundboard sounds
                found = discord.utils.get(guild.soundboard_sounds, id=sound_id)
                if found:
                    sound_name = found.name
                    sound_emoji = str(found.emoji) if found.emoji else "🎵"
                    source_tag = f"Server Sound ({guild.name})"
                else:
                    # 3. Check bot's other shared guilds
                    for g in self.bot.guilds:
                        found = discord.utils.get(g.soundboard_sounds, id=sound_id)
                        if found:
                            sound_name = found.name
                            sound_emoji = str(found.emoji) if found.emoji else "🎵"
                            source_tag = f"External Sound (via {g.name})"
                            break

            if not sound_name:
                sound_name = f"Soundboard Track (`{sound_id}`)"
                source_tag = "External / Nitro Soundboard"

            embed.add_field(name="Sound Title", value=f"{sound_emoji} **{sound_name}**", inline=False)
            embed.add_field(name="Sound Source", value=f"`{source_tag}`", inline=True)

            vol = getattr(sound, "volume", None)
            if vol is not None:
                embed.add_field(name="Volume Played", value=f"`{int(vol * 100)}%`", inline=True)

            if hasattr(sound, "url") and sound.url:
                embed.add_field(name="Audio File", value=f"[▶️ Click to Listen]({sound.url})", inline=True)

        elif effect.emoji:
            embed.title = "✨ Voice Channel Reaction / Effect"
            embed.add_field(name="Effect Emoji", value=str(effect.emoji), inline=False)
        else:
            embed.add_field(name="Effect", value="Voice Channel Sound / Animation", inline=False)

        try:
            await log_channel.send(embed=embed)
            logger.info("Successfully dispatched soundboard log to #%s", log_channel.name)
        except Exception as e:
            logger.warning("Failed posting voice channel effect log: %s", e)

    # ==========================================
    # 3. MEMBER JOIN & LEAVE LOGS
    # ==========================================
    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        guild = member.guild
        log_channel = self._get_target_channel(guild, "joins") or self._get_target_channel(guild, "member")
        if not log_channel:
            return

        now_utc = datetime.now(timezone.utc)
        account_age = now_utc - member.created_at
        is_new_account = account_age.total_seconds() < 86400  # < 24 hours

        embed = discord.Embed(
            title="📥 Member Joined Server",
            color=discord.Color.orange() if is_new_account else discord.Color.green(),
            timestamp=now_utc
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(name="Member", value=f"{member.mention} (`{member.id}`)", inline=True)
        embed.add_field(
            name="Account Created",
            value=f"<t:{int(member.created_at.timestamp())}:F>\n(<t:{int(member.created_at.timestamp())}:R>)",
            inline=True
        )

        if is_new_account:
            embed.add_field(name="⚠️ Security Warning", value="**New account (< 24 hours old)**", inline=False)

        embed.add_field(name="Member Count", value=f"`{guild.member_count}` members", inline=True)
        embed.set_footer(text=f"User ID: {member.id}")

        try:
            await log_channel.send(embed=embed)
        except Exception as e:
            logger.debug("Failed posting member join log: %s", e)

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member):
        guild = member.guild
        log_channel = self._get_target_channel(guild, "leaves") or self._get_target_channel(guild, "member")
        if not log_channel:
            return

        now_utc = datetime.now(timezone.utc)
        embed = discord.Embed(
            title="📤 Member Left Server",
            color=discord.Color.dark_grey(),
            timestamp=now_utc
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(name="Member", value=f"{member.name} (`{member.id}`)", inline=True)

        if member.joined_at:
            embed.add_field(
                name="Joined Server",
                value=f"<t:{int(member.joined_at.timestamp())}:R>",
                inline=True
            )

        # List non-everyone roles
        roles_list = [r.mention for r in member.roles if not r.is_default()]
        if roles_list:
            embed.add_field(name="Roles Held", value=" ".join(roles_list[:10]), inline=False)

        embed.add_field(name="Remaining Members", value=f"`{guild.member_count}` members", inline=True)
        embed.set_footer(text=f"User ID: {member.id}")

        try:
            await log_channel.send(embed=embed)
        except Exception as e:
            logger.debug("Failed posting member leave log: %s", e)

    # ==========================================
    # 4. MOD LOGS (Who Did What to Whom + Reason)
    # ==========================================
    @commands.Cog.listener()
    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry):
        guild = entry.guild
        log_channel = self._get_target_channel(guild, "mod")
        if not log_channel:
            return

        embed = None
        now_utc = datetime.now(timezone.utc)
        mod_user = entry.user
        try:
            target = entry.target
        except Exception:
            target = None

        target_display = getattr(target, "mention", None) or getattr(target, "name", None)
        if not target_display:
            tid = getattr(entry, "_target_id", None)
            target_display = f"<@{tid}>" if tid else "Unknown"

        target_id_str = getattr(target, "id", getattr(entry, "_target_id", "Unknown"))
        reason = entry.reason or "*No reason specified*"

        # BAN
        if entry.action == discord.AuditLogAction.ban:
            embed = discord.Embed(
                title="🔨 Member Banned",
                color=discord.Color.dark_red(),
                timestamp=now_utc
            )
            embed.add_field(name="Target User", value=f"**{target_display}** (`{target_id_str}`)", inline=True)
            embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'} (`{getattr(mod_user, 'id', '')}`)", inline=True)
            embed.add_field(name="Reason", value=reason, inline=False)

        # UNBAN
        elif entry.action == discord.AuditLogAction.unban:
            embed = discord.Embed(
                title="🔓 Member Unbanned",
                color=discord.Color.green(),
                timestamp=now_utc
            )
            embed.add_field(name="Target User", value=f"**{target_display}** (`{target_id_str}`)", inline=True)
            embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
            embed.add_field(name="Reason", value=reason, inline=False)

        # KICK
        elif entry.action == discord.AuditLogAction.kick:
            embed = discord.Embed(
                title="👢 Member Kicked",
                color=discord.Color.orange(),
                timestamp=now_utc
            )
            embed.add_field(name="Target User", value=f"**{target_display}** (`{target_id_str}`)", inline=True)
            embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
            embed.add_field(name="Reason", value=reason, inline=False)

        # TIMEOUT APPLIED OR REMOVED (member_update)
        elif entry.action == discord.AuditLogAction.member_update:
            if hasattr(entry.after, "timed_out_until"):
                tout_after = entry.after.timed_out_until
                if tout_after:
                    embed = discord.Embed(
                        title="⏱️ Member Timed Out",
                        color=discord.Color.gold(),
                        timestamp=now_utc
                    )
                    embed.add_field(name="Target User", value=f"{target_display} (`{target_id_str}`)", inline=True)
                    embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
                    embed.add_field(name="Timeout Expires", value=f"<t:{int(tout_after.timestamp())}:R>", inline=True)
                    embed.add_field(name="Reason", value=reason, inline=False)
                else:
                    embed = discord.Embed(
                        title="⏰ Timeout Lifted / Cleared",
                        color=discord.Color.blue(),
                        timestamp=now_utc
                    )
                    embed.add_field(name="Target User", value=f"{target_display}", inline=True)
                    embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
                    embed.add_field(name="Reason", value=reason, inline=False)

        # SERVER / CHANNEL / ROLE UPDATES (Server settings logs)
        elif entry.action in (discord.AuditLogAction.channel_create, discord.AuditLogAction.channel_delete):
            server_log = self._get_target_channel(guild, "server") or log_channel
            is_create = entry.action == discord.AuditLogAction.channel_create
            embed = discord.Embed(
                title=f"{'📁 Channel Created' if is_create else '🗑️ Channel Deleted'}",
                color=discord.Color.green() if is_create else discord.Color.red(),
                timestamp=now_utc
            )
            embed.add_field(name="Channel Name", value=f"`{target_display}`", inline=True)
            embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
            log_channel = server_log

        elif entry.action in (discord.AuditLogAction.role_create, discord.AuditLogAction.role_delete):
            server_log = self._get_target_channel(guild, "server") or log_channel
            is_create = entry.action == discord.AuditLogAction.role_create
            embed = discord.Embed(
                title=f"{'🛡️ Role Created' if is_create else '🗑️ Role Deleted'}",
                color=discord.Color.green() if is_create else discord.Color.red(),
                timestamp=now_utc
            )
            embed.add_field(name="Role Name", value=f"`{target_display}`", inline=True)
            embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
            log_channel = server_log

        if embed and log_channel:
            try:
                await log_channel.send(embed=embed)
            except Exception as e:
                logger.debug("Failed posting mod audit log: %s", e)

    # ==========================================
    # 5. DEDICATED GRANULAR EVENT LISTENERS
    # ==========================================
    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: Union[discord.User, discord.Member]):
        log_channel = self._get_target_channel(guild, "ban") or self._get_target_channel(guild, "mod")
        if not log_channel:
            return

        embed = discord.Embed(
            title="🔨 Member Banned",
            color=discord.Color.dark_red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.add_field(name="User", value=f"{user.mention} (`{user.name}` | `{user.id}`)", inline=True)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_member_unban(self, guild: discord.Guild, user: discord.User):
        log_channel = self._get_target_channel(guild, "ban") or self._get_target_channel(guild, "mod")
        if not log_channel:
            return

        embed = discord.Embed(
            title="🔓 Member Unbanned",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.add_field(name="User", value=f"{user.mention} (`{user.name}` | `{user.id}`)", inline=True)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel):
        guild = channel.guild
        log_channel = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")
        if not log_channel:
            return

        embed = discord.Embed(
            title="📁 Channel Created",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Channel", value=f"{channel.mention} (`#{channel.name}`)", inline=True)
        embed.add_field(name="Type", value=f"`{str(channel.type).capitalize()}`", inline=True)
        if getattr(channel, "category", None):
            embed.add_field(name="Category", value=f"`{channel.category.name}`", inline=True)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel):
        guild = channel.guild
        log_channel = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")
        if not log_channel:
            return

        embed = discord.Embed(
            title="🗑️ Channel Deleted",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Channel Name", value=f"`#{channel.name}` (`{channel.id}`)", inline=True)
        embed.add_field(name="Type", value=f"`{str(channel.type).capitalize()}`", inline=True)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
        guild = after.guild
        log_channel = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")
        if not log_channel:
            return

        changes = []
        if before.name != after.name:
            changes.append(f"• **Name:** `#{before.name}` ➔ `#{after.name}`")
        if getattr(before, "topic", None) != getattr(after, "topic", None):
            changes.append("• **Topic changed**")
        if getattr(before, "slowmode_delay", None) != getattr(after, "slowmode_delay", None):
            changes.append(f"• **Slowmode:** `{before.slowmode_delay}s` ➔ `{after.slowmode_delay}s`")

        if not changes:
            return

        embed = discord.Embed(
            title="⚙️ Channel Updated",
            color=discord.Color.blue(),
            description="\n".join(changes),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Channel", value=after.mention, inline=False)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role):
        guild = role.guild
        log_channel = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server")
        if not log_channel:
            return

        embed = discord.Embed(
            title="🛡️ Role Created",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Role", value=f"{role.mention} (`{role.name}` | `{role.id}`)", inline=True)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role):
        guild = role.guild
        log_channel = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server")
        if not log_channel:
            return

        embed = discord.Embed(
            title="🗑️ Role Deleted",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Role Name", value=f"`{role.name}` (`{role.id}`)", inline=True)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role):
        guild = after.guild
        log_channel = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server")
        if not log_channel:
            return

        changes = []
        if before.name != after.name:
            changes.append(f"• **Name:** `{before.name}` ➔ `{after.name}`")
        if before.color != after.color:
            changes.append(f"• **Color:** `{before.color}` ➔ `{after.color}`")
        if before.permissions != after.permissions:
            changes.append("• **Permissions modified**")

        if not changes:
            return

        embed = discord.Embed(
            title="🛡️ Role Updated",
            color=discord.Color.blue(),
            description="\n".join(changes),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Role", value=after.mention, inline=False)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_update(self, before: discord.Guild, after: discord.Guild):
        log_channel = self._get_target_channel(after, "server")
        if not log_channel:
            return

        changes = []
        if before.name != after.name:
            changes.append(f"• **Server Name:** `{before.name}` ➔ `{after.name}`")
        if before.icon != after.icon:
            changes.append("• **Server Icon updated**")
        if before.banner != after.banner:
            changes.append("• **Server Banner updated**")
        if before.afk_channel != after.afk_channel:
            changes.append(f"• **AFK Channel:** {getattr(after.afk_channel, 'mention', 'None')}")

        if not changes:
            return

        embed = discord.Embed(
            title="🏢 Server Settings Updated",
            color=discord.Color.gold(),
            description="\n".join(changes),
            timestamp=datetime.now(timezone.utc)
        )
        if after.icon:
            embed.set_thumbnail(url=after.icon.url)
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        guild = after.guild

        # 1. Nickname changed -> member log
        if before.nick != after.nick:
            mem_ch = self._get_target_channel(guild, "member")
            if mem_ch:
                embed = discord.Embed(
                    title="👤 Member Nickname Changed",
                    color=discord.Color.blue(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.set_author(name=str(after), icon_url=after.display_avatar.url)
                embed.add_field(name="Member", value=after.mention, inline=True)
                embed.add_field(name="Before", value=f"`{before.nick or before.name}`", inline=True)
                embed.add_field(name="After", value=f"`{after.nick or after.name}`", inline=True)
                try:
                    await mem_ch.send(embed=embed)
                except Exception:
                    pass

        # 2. Roles changed -> role log
        if before.roles != after.roles:
            role_ch = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server")
            if role_ch:
                added = [r for r in after.roles if r not in before.roles]
                removed = [r for r in before.roles if r not in after.roles]
                changes = []
                if added:
                    changes.append(f"➕ **Added:** {', '.join([r.mention for r in added])}")
                if removed:
                    changes.append(f"➖ **Removed:** {', '.join([r.mention for r in removed])}")

                if changes:
                    embed = discord.Embed(
                        title="🛡️ Member Roles Updated",
                        color=discord.Color.blue(),
                        description="\n".join(changes),
                        timestamp=datetime.now(timezone.utc)
                    )
                    embed.set_author(name=str(after), icon_url=after.display_avatar.url)
                    embed.add_field(name="Member", value=after.mention, inline=False)
                    try:
                        await role_ch.send(embed=embed)
                    except Exception:
                        pass

        # 3. Server Boosted -> boost log
        if before.premium_since != after.premium_since and after.premium_since:
            boost_ch = self._get_target_channel(guild, "boost") or self._get_target_channel(guild, "server")
            if boost_ch:
                embed = discord.Embed(
                    title="🚀 Server Boosted!",
                    color=discord.Color.magenta(),
                    description=f"{after.mention} just boosted **{guild.name}**!",
                    timestamp=datetime.now(timezone.utc)
                )
                embed.set_thumbnail(url=after.display_avatar.url)
                embed.add_field(name="Total Server Boosts", value=f"`{guild.premium_subscription_count}` boosts", inline=True)
                embed.add_field(name="Tier Level", value=f"Tier `{guild.premium_tier}`", inline=True)
                try:
                    await boost_ch.send(embed=embed)
                except Exception:
                    pass

    @commands.Cog.listener()
    async def on_invite_create(self, invite: discord.Invite):
        guild = invite.guild
        if not guild:
            return
        inv_ch = self._get_target_channel(guild, "invite") or self._get_target_channel(guild, "server")
        if not inv_ch:
            return

        embed = discord.Embed(
            title="✉️ Invite Created",
            color=discord.Color.teal(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Code", value=f"`{invite.code}` ([Link]({invite.url}))", inline=True)
        embed.add_field(name="Created By", value=f"{invite.inviter.mention if invite.inviter else 'Unknown'}", inline=True)
        embed.add_field(name="Channel", value=f"{getattr(invite.channel, 'mention', 'Unknown')}", inline=True)
        max_uses_str = str(invite.max_uses) if invite.max_uses else "Unlimited"
        embed.add_field(name="Max Uses", value=f"`{max_uses_str}`", inline=True)
        try:
            await inv_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_invite_delete(self, invite: discord.Invite):
        guild = invite.guild
        if not guild:
            return
        inv_ch = self._get_target_channel(guild, "invite") or self._get_target_channel(guild, "server")
        if not inv_ch:
            return

        embed = discord.Embed(
            title="🗑️ Invite Deleted",
            color=discord.Color.dark_grey(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Code", value=f"`{invite.code}`", inline=True)
        embed.add_field(name="Channel", value=f"{getattr(invite.channel, 'mention', 'Unknown')}", inline=True)
        try:
            await inv_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_integrations_update(self, guild: discord.Guild):
        rel_ch = self._get_target_channel(guild, "relationship") or self._get_target_channel(guild, "server")
        if not rel_ch:
            return
        embed = discord.Embed(
            title="🔗 Integrations & Bots Updated",
            color=discord.Color.blue(),
            description=f"Server integrations, apps, or webhooks updated in **{guild.name}**.",
            timestamp=datetime.now(timezone.utc)
        )
        try:
            await rel_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_bulk_message_delete(self, messages: list):
        if not messages:
            return
        guild = messages[0].guild
        if not guild:
            return
        msg_ch = self._get_target_channel(guild, "message") or self._get_target_channel(guild, "chat")
        if not msg_ch:
            return

        embed = discord.Embed(
            title=f"🧹 Bulk Messages Purged in #{messages[0].channel.name}",
            color=discord.Color.red(),
            description=f"**{len(messages)}** messages were deleted in {messages[0].channel.mention}.",
            timestamp=datetime.now(timezone.utc)
        )
        try:
            await msg_ch.send(embed=embed)
        except Exception:
            pass

async def setup(bot: commands.Bot):
    await bot.add_cog(LoggingSystem(bot))

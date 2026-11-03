"""Comprehensive Audit & Logging Suite Cog.
Logs Chat (edits/deletions), Voice (joins/leaves/switches), Members (joins/leaves),
and Moderation Actions (who banned/kicked/timed out whom + reasons) into dedicated channels.
"""
import time
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Any, Dict, Tuple, Sequence
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

def format_role_list(role_list: List[Any]) -> str:
    """Formats a list of roles into readable mentions or names."""
    res = []
    for r in role_list:
        if hasattr(r, "mention"):
            res.append(r.mention)
        elif hasattr(r, "name"):
            res.append(f"@{r.name}")
        elif hasattr(r, "id"):
            res.append(f"<@&{r.id}>")
        else:
            res.append(str(r))
    return ", ".join(res) if res else "*None*"

class LoggingSystem(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # (guild_id, target_id, added_ids_tuple, removed_ids_tuple) -> timestamp
        self.recent_role_events: Dict[Tuple, float] = {}
        # (guild_id, user_id, action_type) -> timestamp
        self.recent_mod_events: Dict[Tuple, float] = {}

    def _get_target_channel(self, guild: discord.Guild, category: str) -> Optional[discord.TextChannel]:
        """Resolves the dedicated log channel for a category in a guild."""
        ch_id = bot_config.get_log_channel_id(guild.id, category)
        if ch_id:
            ch = guild.get_channel(ch_id)
            if isinstance(ch, discord.TextChannel):
                return ch
        return None

    def _prune_recent_caches(self):
        """Cleans up in-memory dedup caches older than 30s."""
        now = time.time()
        for k in list(self.recent_role_events.keys()):
            if now - self.recent_role_events[k] > 30:
                del self.recent_role_events[k]
        for k in list(self.recent_mod_events.keys()):
            if now - self.recent_mod_events[k] > 30:
                del self.recent_mod_events[k]

    async def _send_role_change_log(
        self,
        channel: discord.TextChannel,
        target: Union[discord.Member, discord.User],
        added: List[Any],
        removed: List[Any],
        actor: Optional[Union[discord.Member, discord.User]],
        reason: Optional[str]
    ):
        """Dispatches an explicit log showing who gave role to whom, or who removed role from whom."""
        now_ts = datetime.now(timezone.utc)
        target_display = target.mention if hasattr(target, "mention") else f"<@{getattr(target, 'id', 'Unknown')}>"
        target_name = f"{getattr(target, 'name', 'Unknown')}"
        target_id = getattr(target, 'id', 'Unknown')
        avatar_url = getattr(target, 'display_avatar', None)
        avatar_url = avatar_url.url if avatar_url else None

        actor_str = f"{actor.mention} (`{actor.name}` | ID: `{actor.id}`)" if actor else "*Discord System / Integration*"

        # 1. Roles Added Only -> Who Gave Role to Whom
        if added and not removed:
            embed = discord.Embed(
                title="➕ Role Given to Member",
                color=discord.Color.green(),
                timestamp=now_ts
            )
            embed.description = f"{actor.mention if actor else 'System'} gave role(s) to {target_display}."
            if avatar_url:
                embed.set_thumbnail(url=avatar_url)
            embed.add_field(name="👤 Member (Target)", value=f"{target_display} (`{target_name}` | ID: `{target_id}`)", inline=True)
            embed.add_field(name="🛠️ Given By (Moderator)", value=actor_str, inline=True)
            embed.add_field(name="🏷️ Role(s) Added", value=format_role_list(added), inline=False)
            if reason:
                embed.add_field(name="📝 Reason", value=f"`{reason}`", inline=False)

        # 2. Roles Removed Only -> Who Removed Role from Whom
        elif removed and not added:
            embed = discord.Embed(
                title="➖ Role Removed from Member",
                color=discord.Color.red(),
                timestamp=now_ts
            )
            embed.description = f"{actor.mention if actor else 'System'} removed role(s) from {target_display}."
            if avatar_url:
                embed.set_thumbnail(url=avatar_url)
            embed.add_field(name="👤 Member (Target)", value=f"{target_display} (`{target_name}` | ID: `{target_id}`)", inline=True)
            embed.add_field(name="🛠️ Removed By (Moderator)", value=actor_str, inline=True)
            embed.add_field(name="🏷️ Role(s) Removed", value=format_role_list(removed), inline=False)
            if reason:
                embed.add_field(name="📝 Reason", value=f"`{reason}`", inline=False)

        # 3. Both Roles Added and Removed
        else:
            embed = discord.Embed(
                title="🛡️ Member Roles Updated",
                color=discord.Color.blue(),
                timestamp=now_ts
            )
            embed.description = f"{actor.mention if actor else 'System'} modified roles for {target_display}."
            if avatar_url:
                embed.set_thumbnail(url=avatar_url)
            embed.add_field(name="👤 Member (Target)", value=f"{target_display} (`{target_name}` | ID: `{target_id}`)", inline=True)
            embed.add_field(name="🛠️ Modified By (Moderator)", value=actor_str, inline=True)
            if added:
                embed.add_field(name="➕ Role(s) Added", value=format_role_list(added), inline=False)
            if removed:
                embed.add_field(name="➖ Role(s) Removed", value=format_role_list(removed), inline=False)
            if reason:
                embed.add_field(name="📝 Reason", value=f"`{reason}`", inline=False)

        embed.set_footer(text=f"Target ID: {target_id}")
        try:
            await channel.send(embed=embed)
        except Exception as e:
            logger.debug("Failed sending role change log: %s", e)

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

        # Prioritize dedicated soundboard log channel; fall back to vc_state, voice, or alert channel
        log_channel = (
            self._get_target_channel(guild, "soundboard")
            or self._get_target_channel(guild, "vc_state")
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
        if not guild:
            return

        self._prune_recent_caches()

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
            log_channel = self._get_target_channel(guild, "ban") or self._get_target_channel(guild, "mod")
            if not log_channel:
                return
            dedup_key = (guild.id, getattr(target, "id", 0), "ban")
            self.recent_mod_events[dedup_key] = time.time()
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
            log_channel = self._get_target_channel(guild, "ban") or self._get_target_channel(guild, "mod")
            if not log_channel:
                return
            dedup_key = (guild.id, getattr(target, "id", 0), "unban")
            self.recent_mod_events[dedup_key] = time.time()
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
            log_channel = self._get_target_channel(guild, "kick") or self._get_target_channel(guild, "mod")
            if not log_channel:
                return
            dedup_key = (guild.id, getattr(target, "id", 0), "kick")
            self.recent_mod_events[dedup_key] = time.time()
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
            log_channel = self._get_target_channel(guild, "timeout") or self._get_target_channel(guild, "mod")
            if not log_channel:
                return
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

        # WHO GAVE ROLE TO WHOM / WHO REMOVED ROLE TO WHOM (member_role_update)
        elif entry.action == discord.AuditLogAction.member_role_update:
            role_log = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server") or self._get_target_channel(guild, "mod")
            if not role_log:
                return

            roles_added = []
            roles_removed = []
            if hasattr(entry, "changes") and entry.changes:
                after_obj = getattr(entry.changes, "after", None)
                before_obj = getattr(entry.changes, "before", None)
                if after_obj and hasattr(after_obj, "roles"):
                    roles_added = getattr(after_obj, "roles", []) or []
                if before_obj and hasattr(before_obj, "roles"):
                    roles_removed = getattr(before_obj, "roles", []) or []

            tid = getattr(target, "id", getattr(entry, "_target_id", 0))
            dedup_key = (
                guild.id,
                tid,
                tuple(sorted(getattr(r, "id", 0) for r in roles_added)),
                tuple(sorted(getattr(r, "id", 0) for r in roles_removed))
            )
            self.recent_role_events[dedup_key] = time.time()
            await self._send_role_change_log(role_log, target, roles_added, roles_removed, mod_user, entry.reason)
            return

        # SERVER / CHANNEL / ROLE UPDATES (Server settings logs)
        elif entry.action in (discord.AuditLogAction.channel_create, discord.AuditLogAction.channel_delete):
            server_log = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server") or self._get_target_channel(guild, "mod")
            if not server_log:
                return
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
            server_log = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server") or self._get_target_channel(guild, "mod")
            if not server_log:
                return
            is_create = entry.action == discord.AuditLogAction.role_create
            embed = discord.Embed(
                title=f"{'🛡️ Role Created' if is_create else '🗑️ Role Deleted'}",
                color=discord.Color.green() if is_create else discord.Color.red(),
                timestamp=now_utc
            )
            embed.add_field(name="Role Name", value=f"`{target_display}`", inline=True)
            embed.add_field(name="Moderator", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
            log_channel = server_log

        # BOT ADD / WEBHOOK INTEGRATIONS
        elif entry.action in (discord.AuditLogAction.bot_add, discord.AuditLogAction.webhook_create, discord.AuditLogAction.webhook_delete):
            rel_log = self._get_target_channel(guild, "relationship") or self._get_target_channel(guild, "admin") or self._get_target_channel(guild, "server")
            if not rel_log:
                return
            action_name = "Bot Added" if entry.action == discord.AuditLogAction.bot_add else ("Webhook Created" if entry.action == discord.AuditLogAction.webhook_create else "Webhook Deleted")
            embed = discord.Embed(
                title=f"🔗 Integration: {action_name}",
                color=discord.Color.teal(),
                timestamp=now_utc
            )
            embed.add_field(name="Target", value=f"**{target_display}** (`{target_id_str}`)", inline=True)
            embed.add_field(name="Actor", value=f"{mod_user.mention if mod_user else 'Unknown'}", inline=True)
            log_channel = rel_log

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
        dedup_key = (guild.id, user.id, "ban")
        if dedup_key in self.recent_mod_events and (time.time() - self.recent_mod_events[dedup_key]) < 8:
            return

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
        dedup_key = (guild.id, user.id, "unban")
        if dedup_key in self.recent_mod_events and (time.time() - self.recent_mod_events[dedup_key]) < 8:
            return

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

    @staticmethod
    def _format_perm_name(perm: str) -> str:
        name_map = {
            "read_messages": "View Channel",
            "view_channel": "View Channel",
            "send_messages": "Send Messages",
            "manage_messages": "Manage Messages",
            "manage_channels": "Manage Channel",
            "manage_permissions": "Manage Permissions",
            "manage_webhooks": "Manage Webhooks",
            "create_instant_invite": "Create Invite",
            "embed_links": "Embed Links",
            "attach_files": "Attach Files",
            "read_message_history": "Read Message History",
            "mention_everyone": "Mention Everyone",
            "use_external_emojis": "Use External Emojis",
            "use_external_stickers": "Use External Stickers",
            "add_reactions": "Add Reactions",
            "connect": "Connect",
            "speak": "Speak",
            "mute_members": "Mute Members",
            "deafen_members": "Deafen Members",
            "move_members": "Move Members",
            "use_voice_activation": "Voice Activity",
            "priority_speaker": "Priority Speaker",
            "stream": "Video / Screen Share",
            "use_soundboard": "Use Soundboard",
            "use_external_sounds": "Use External Sounds",
            "send_voice_messages": "Send Voice Messages",
            "create_public_threads": "Create Public Threads",
            "create_private_threads": "Create Private Threads",
            "send_messages_in_threads": "Send Messages in Threads",
            "manage_threads": "Manage Threads"
        }
        return name_map.get(perm, perm.replace("_", " ").title())

    @classmethod
    def _get_active_perms(cls, ow: discord.PermissionOverwrite) -> Tuple[List[str], List[str]]:
        allowed = []
        denied = []
        for perm, val in ow:
            name = cls._format_perm_name(perm)
            if val is True:
                allowed.append(name)
            elif val is False:
                denied.append(name)
        return allowed, denied

    async def _lookup_channel_moderator(
        self,
        guild: discord.Guild,
        channel_id: int,
        action: discord.AuditLogAction,
        extra_target_id: Optional[int] = None,
        max_age_seconds: float = 8.0
    ) -> Tuple[Optional[Union[discord.Member, discord.User]], Optional[str]]:
        """Looks up Discord audit log for channel updates or permission overwrite changes."""
        if not guild.me.guild_permissions.view_audit_log:
            return None, None
        try:
            await asyncio.sleep(0.4)
            now_utc = datetime.now(timezone.utc)
            async for entry in guild.audit_logs(limit=6, action=action):
                time_diff = (now_utc - entry.created_at).total_seconds()
                if time_diff < 0 or time_diff > max_age_seconds:
                    continue
                entry_tid = getattr(entry.target, "id", getattr(entry, "_target_id", None))
                if entry_tid != channel_id:
                    continue
                if extra_target_id is not None and entry.extra is not None:
                    extra_id = getattr(entry.extra, "id", None)
                    if extra_id and extra_id != extra_target_id:
                        continue
                return entry.user, entry.reason
        except Exception as e:
            logger.debug("Failed querying audit log for channel action %s: %s", action, e)
        return None, None

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel):
        guild = channel.guild
        if channel.type == discord.ChannelType.news:
            log_channel = self._get_target_channel(guild, "announcement") or self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")
        elif channel.type == discord.ChannelType.stage_voice:
            log_channel = self._get_target_channel(guild, "stage") or self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "voice")
        else:
            log_channel = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")

        if not log_channel:
            return

        mod_user, reason = await self._lookup_channel_moderator(guild, channel.id, discord.AuditLogAction.channel_create)

        embed = discord.Embed(
            title="📁 Channel Created",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Channel", value=f"{channel.mention} (`#{channel.name}`)", inline=True)
        embed.add_field(name="Type", value=f"`{str(channel.type).capitalize()}`", inline=True)
        if getattr(channel, "category", None):
            embed.add_field(name="Category", value=f"`{channel.category.name}`", inline=True)
        if mod_user:
            embed.add_field(name="Created By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
        if reason:
            embed.add_field(name="Reason", value=f"`{reason}`", inline=False)
        embed.set_footer(text=f"Channel ID: {channel.id}")
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel):
        guild = channel.guild
        if channel.type == discord.ChannelType.news:
            log_channel = self._get_target_channel(guild, "announcement") or self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")
        elif channel.type == discord.ChannelType.stage_voice:
            log_channel = self._get_target_channel(guild, "stage") or self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "voice")
        else:
            log_channel = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")

        if not log_channel:
            return

        mod_user, reason = await self._lookup_channel_moderator(guild, channel.id, discord.AuditLogAction.channel_delete)

        embed = discord.Embed(
            title="🗑️ Channel Deleted",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Channel Name", value=f"`#{channel.name}` (`{channel.id}`)", inline=True)
        embed.add_field(name="Type", value=f"`{str(channel.type).capitalize()}`", inline=True)
        if mod_user:
            embed.add_field(name="Deleted By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
        if reason:
            embed.add_field(name="Reason", value=f"`{reason}`", inline=False)
        embed.set_footer(text=f"Channel ID: {channel.id}")
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
        guild = after.guild
        if after.type == discord.ChannelType.news:
            log_channel = self._get_target_channel(guild, "announcement") or self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")
        elif after.type == discord.ChannelType.stage_voice:
            log_channel = self._get_target_channel(guild, "stage") or self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "voice")
        else:
            log_channel = self._get_target_channel(guild, "channel") or self._get_target_channel(guild, "server")

        if not log_channel:
            return

        # -------------------------------------------------------------
        # 1. CHANNEL ATTRIBUTE CHANGES (Name, Topic, Slowmode, Category, NSFW)
        # -------------------------------------------------------------
        channel_changes = []
        if before.name != after.name:
            channel_changes.append(f"• **Name:** `#{before.name}` ➔ `#{after.name}`")
        if getattr(before, "topic", None) != getattr(after, "topic", None):
            b_top = getattr(before, "topic", None) or "*None*"
            a_top = getattr(after, "topic", None) or "*None*"
            channel_changes.append(f"• **Topic:** {b_top} ➔ {a_top}")
        if getattr(before, "slowmode_delay", None) != getattr(after, "slowmode_delay", None):
            channel_changes.append(f"• **Slowmode:** `{getattr(before, 'slowmode_delay', 0)}s` ➔ `{getattr(after, 'slowmode_delay', 0)}s`")
        if getattr(before, "category", None) != getattr(after, "category", None):
            b_cat = before.category.name if getattr(before, "category", None) else "*None*"
            a_cat = after.category.name if getattr(after, "category", None) else "*None*"
            channel_changes.append(f"• **Category:** `{b_cat}` ➔ `{a_cat}`")
        if getattr(before, "nsfw", None) != getattr(after, "nsfw", None):
            channel_changes.append(f"• **NSFW Status:** `{getattr(before, 'nsfw', False)}` ➔ `{getattr(after, 'nsfw', False)}`")

        if channel_changes:
            mod_user, reason = await self._lookup_channel_moderator(
                guild, channel_id=after.id,
                action=discord.AuditLogAction.channel_update
            )
            embed = discord.Embed(
                title="⚙️ Channel Settings Updated",
                color=discord.Color.blue(),
                description="\n".join(channel_changes),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(name="Channel", value=f"{after.mention} (`#{after.name}`)", inline=True)
            if mod_user:
                embed.add_field(name="Updated By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
            if reason:
                embed.add_field(name="Reason", value=f"`{reason}`", inline=False)
            embed.set_footer(text=f"Channel ID: {after.id}")
            try:
                await log_channel.send(embed=embed)
            except Exception:
                pass

        # -------------------------------------------------------------
        # 2. OVERWRITES REMOVED (Roles or Members removed from channel)
        # -------------------------------------------------------------
        before_ow_map = dict(before.overwrites)
        after_ow_map = dict(after.overwrites)

        for target, before_ow in before_ow_map.items():
            if target not in after_ow_map:
                is_role = isinstance(target, discord.Role)
                target_type = "Role" if is_role else "Member"
                target_id = getattr(target, "id", None)

                mod_user, reason = await self._lookup_channel_moderator(
                    guild, channel_id=after.id,
                    action=discord.AuditLogAction.overwrite_delete,
                    extra_target_id=target_id
                )

                embed = discord.Embed(
                    title=f"🚫 {target_type} Removed from Channel",
                    color=discord.Color.red(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="Channel", value=f"{after.mention} (`#{after.name}`)", inline=True)
                if is_role:
                    embed.add_field(name="Removed Role", value=f"{target.mention} (`{target.name}` | `{target.id}`)", inline=True)
                else:
                    embed.add_field(name="Removed Member", value=f"{target.mention} (`{target.name}` | `{target.id}`)", inline=True)

                if mod_user:
                    embed.add_field(name="Removed By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
                else:
                    embed.add_field(name="Removed By", value="*Unavailable in Audit Log*", inline=True)

                if reason:
                    embed.add_field(name="Reason", value=f"`{reason}`", inline=False)

                allowed_prev, denied_prev = self._get_active_perms(before_ow)
                if allowed_prev:
                    embed.add_field(name="Revoked Allowed Permissions", value=", ".join(allowed_prev[:12]) + ("..." if len(allowed_prev) > 12 else ""), inline=False)
                if denied_prev:
                    embed.add_field(name="Revoked Denied Overwrites", value=", ".join(denied_prev[:12]) + ("..." if len(denied_prev) > 12 else ""), inline=False)

                embed.set_footer(text=f"Channel ID: {after.id}")
                try:
                    await log_channel.send(embed=embed)
                except Exception:
                    pass

        # -------------------------------------------------------------
        # 3. OVERWRITES MODIFIED (Removing Perms or Denying/Granting Perms)
        # -------------------------------------------------------------
        for target, after_ow in after_ow_map.items():
            if target in before_ow_map:
                before_ow = before_ow_map[target]
                if before_ow != after_ow:
                    removed_or_denied = []
                    granted = []
                    reset_neutral = []

                    for perm, before_val in before_ow:
                        after_val = getattr(after_ow, perm)
                        if before_val == after_val:
                            continue
                        p_name = self._format_perm_name(perm)
                        if before_val is True and after_val is False:
                            removed_or_denied.append(f"⛔ **{p_name}**: `Allowed` ➔ `Denied`")
                        elif before_val is True and after_val is None:
                            removed_or_denied.append(f"⚪ **{p_name}**: `Allowed` ➔ `Removed (Default)`")
                        elif before_val is None and after_val is False:
                            removed_or_denied.append(f"❌ **{p_name}**: `Default` ➔ `Denied`")
                        elif before_val is False and after_val is None:
                            reset_neutral.append(f"⚪ **{p_name}**: `Denied` ➔ `Removed (Default)`")
                        elif before_val is not True and after_val is True:
                            granted.append(f"✅ **{p_name}**: `Granted`")

                    if removed_or_denied or granted or reset_neutral:
                        target_id = getattr(target, "id", None)
                        mod_user, reason = await self._lookup_channel_moderator(
                            guild, channel_id=after.id,
                            action=discord.AuditLogAction.overwrite_update,
                            extra_target_id=target_id
                        )
                        is_role = isinstance(target, discord.Role)
                        target_type = "Role" if is_role else "Member"

                        if removed_or_denied:
                            title = f"🔒 Channel Permissions Removed / Denied ({target_type})"
                            color = discord.Color.orange()
                        elif granted:
                            title = f"🔓 Channel Permissions Granted ({target_type})"
                            color = discord.Color.green()
                        else:
                            title = f"⚙️ Channel Permissions Reset ({target_type})"
                            color = discord.Color.blue()

                        embed = discord.Embed(
                            title=title,
                            color=color,
                            timestamp=datetime.now(timezone.utc)
                        )
                        embed.add_field(name="Channel", value=f"{after.mention} (`#{after.name}`)", inline=True)
                        if is_role:
                            embed.add_field(name="Role", value=f"{target.mention} (`{target.name}` | `{target.id}`)", inline=True)
                        else:
                            embed.add_field(name="Member", value=f"{target.mention} (`{target.name}` | `{target.id}`)", inline=True)

                        if mod_user:
                            embed.add_field(name="Action By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
                        else:
                            embed.add_field(name="Action By", value="*Unavailable in Audit Log*", inline=True)

                        if reason:
                            embed.add_field(name="Reason", value=f"`{reason}`", inline=False)

                        if removed_or_denied:
                            embed.add_field(name="🚫 Permissions Removed / Denied", value="\n".join(removed_or_denied[:12]), inline=False)
                        if granted:
                            embed.add_field(name="✅ Permissions Granted", value="\n".join(granted[:12]), inline=False)
                        if reset_neutral and not removed_or_denied:
                            embed.add_field(name="⚪ Permissions Reset to Default", value="\n".join(reset_neutral[:12]), inline=False)

                        embed.set_footer(text=f"Channel ID: {after.id}")
                        try:
                            await log_channel.send(embed=embed)
                        except Exception:
                            pass

        # -------------------------------------------------------------
        # 4. OVERWRITES ADDED (Roles or Members added to channel)
        # -------------------------------------------------------------
        for target, after_ow in after_ow_map.items():
            if target not in before_ow_map:
                is_role = isinstance(target, discord.Role)
                target_type = "Role" if is_role else "Member"
                target_id = getattr(target, "id", None)

                mod_user, reason = await self._lookup_channel_moderator(
                    guild, channel_id=after.id,
                    action=discord.AuditLogAction.overwrite_create,
                    extra_target_id=target_id
                )
                embed = discord.Embed(
                    title=f"🛡️ {target_type} Added to Channel Overwrites",
                    color=discord.Color.green(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="Channel", value=f"{after.mention} (`#{after.name}`)", inline=True)
                if is_role:
                    embed.add_field(name="Added Role", value=f"{target.mention} (`{target.name}` | `{target.id}`)", inline=True)
                else:
                    embed.add_field(name="Added Member", value=f"{target.mention} (`{target.name}` | `{target.id}`)", inline=True)

                if mod_user:
                    embed.add_field(name="Added By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
                else:
                    embed.add_field(name="Added By", value="*Unavailable in Audit Log*", inline=True)

                if reason:
                    embed.add_field(name="Reason", value=f"`{reason}`", inline=False)

                allowed_new, denied_new = self._get_active_perms(after_ow)
                if allowed_new:
                    embed.add_field(name="Granted Permissions", value=", ".join(allowed_new[:12]) + ("..." if len(allowed_new) > 12 else ""), inline=False)
                if denied_new:
                    embed.add_field(name="Denied Permissions", value=", ".join(denied_new[:12]) + ("..." if len(denied_new) > 12 else ""), inline=False)

                embed.set_footer(text=f"Channel ID: {after.id}")
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
            b_afk = before.afk_channel.mention if before.afk_channel else "*None*"
            a_afk = after.afk_channel.mention if after.afk_channel else "*None*"
            changes.append(f"• **AFK Channel:** {b_afk} ➔ {a_afk}")
        if getattr(before, "description", None) != getattr(after, "description", None):
            changes.append("• **Server Description updated**")
        if getattr(before, "rules_channel", None) != getattr(after, "rules_channel", None):
            b_rules = before.rules_channel.mention if before.rules_channel else "*None*"
            a_rules = after.rules_channel.mention if after.rules_channel else "*None*"
            changes.append(f"• **Rules Channel:** {b_rules} ➔ {a_rules}")
        if getattr(before, "verification_level", None) != getattr(after, "verification_level", None):
            changes.append(f"• **Verification Level:** `{before.verification_level}` ➔ `{after.verification_level}`")

        if not changes:
            return

        mod_user = None
        if after.me.guild_permissions.view_audit_log:
            try:
                await asyncio.sleep(0.4)
                now_utc = datetime.now(timezone.utc)
                async for entry in after.audit_logs(limit=4, action=discord.AuditLogAction.guild_update):
                    if abs((now_utc - entry.created_at).total_seconds()) < 10:
                        mod_user = entry.user
                        break
            except Exception:
                pass

        embed = discord.Embed(
            title="🏢 Server Settings Updated",
            color=discord.Color.gold(),
            description="\n".join(changes),
            timestamp=datetime.now(timezone.utc)
        )
        if mod_user:
            embed.add_field(name="Updated By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
        if after.icon:
            embed.set_thumbnail(url=after.icon.url)
        embed.set_footer(text=f"Server ID: {after.id}")
        try:
            await log_channel.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        guild = after.guild

        # 1. Nickname changed -> member log
        if before.nick != after.nick:
            mem_ch = self._get_target_channel(guild, "member") or self._get_target_channel(guild, "server") or self._get_target_channel(guild, "mod")
            if mem_ch:
                mod_user = None
                audit_reason = None
                if guild.me.guild_permissions.view_audit_log:
                    try:
                        await asyncio.sleep(0.4)
                        now_utc = datetime.now(timezone.utc)
                        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.member_update):
                            if entry.target and entry.target.id == after.id:
                                if abs((now_utc - entry.created_at).total_seconds()) < 10:
                                    mod_user = entry.user
                                    audit_reason = entry.reason
                                    break
                    except Exception as e:
                        logger.debug("Failed querying audit log for member nickname update: %s", e)

                if before.nick and not after.nick:
                    title = "👤 Member Nickname Removed / Reset"
                    color = discord.Color.orange()
                    b_str = f"`{before.nick}`"
                    a_str = f"*Reset to username* (`{after.name}`)"
                elif not before.nick and after.nick:
                    title = "👤 Member Nickname Added"
                    color = discord.Color.green()
                    b_str = f"*None* (`{before.name}`)"
                    a_str = f"`{after.nick}`"
                else:
                    title = "👤 Member Nickname Changed"
                    color = discord.Color.blue()
                    b_str = f"`{before.nick}`"
                    a_str = f"`{after.nick}`"

                embed = discord.Embed(
                    title=title,
                    color=color,
                    timestamp=datetime.now(timezone.utc)
                )
                embed.set_author(name=str(after), icon_url=after.display_avatar.url)
                embed.add_field(name="Member", value=f"{after.mention} (`{after.name}` | `{after.id}`)", inline=False)
                embed.add_field(name="Before", value=b_str, inline=True)
                embed.add_field(name="After", value=a_str, inline=True)

                if mod_user:
                    if mod_user.id == after.id:
                        embed.add_field(name="Changed By", value=f"{after.mention} *(Self)*", inline=True)
                    else:
                        embed.add_field(name="Changed By", value=f"{mod_user.mention} (`{mod_user.name}` | `{mod_user.id}`)", inline=True)
                else:
                    embed.add_field(name="Changed By", value=f"{after.mention} *(Self or Staff)*", inline=True)

                if audit_reason:
                    embed.add_field(name="Reason", value=f"`{audit_reason}`", inline=False)

                embed.set_footer(text=f"User ID: {after.id}")
                try:
                    await mem_ch.send(embed=embed)
                except Exception:
                    pass

        # 1b. Server-specific Avatar changed -> member log
        if getattr(before, "guild_avatar", None) != getattr(after, "guild_avatar", None):
            mem_ch = self._get_target_channel(guild, "member") or self._get_target_channel(guild, "server")
            if mem_ch:
                embed = discord.Embed(
                    title="🖼️ Member Server Avatar Changed",
                    color=discord.Color.blue(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.set_author(name=str(after), icon_url=after.display_avatar.url)
                embed.add_field(name="Member", value=f"{after.mention} (`{after.name}` | `{after.id}`)", inline=True)
                if after.guild_avatar:
                    embed.set_thumbnail(url=after.guild_avatar.url)
                    embed.add_field(name="Status", value="Server avatar updated", inline=True)
                else:
                    embed.add_field(name="Status", value="Server avatar removed (reverted to global avatar)", inline=True)
                embed.set_footer(text=f"User ID: {after.id}")
                try:
                    await mem_ch.send(embed=embed)
                except Exception:
                    pass

        # 2. Roles changed -> role log (Who gave role to whom / Who removed role from whom)
        if before.roles != after.roles:
            added = [r for r in after.roles if r not in before.roles]
            removed = [r for r in before.roles if r not in after.roles]
            if added or removed:
                role_ch = self._get_target_channel(guild, "role") or self._get_target_channel(guild, "server") or self._get_target_channel(guild, "mod")
                if role_ch:
                    dedup_key = (
                        guild.id,
                        after.id,
                        tuple(sorted(r.id for r in added)),
                        tuple(sorted(r.id for r in removed))
                    )
                    now_sec = time.time()
                    if dedup_key not in self.recent_role_events or (now_sec - self.recent_role_events[dedup_key]) >= 8:
                        # Slight delay so audit log is written
                        await asyncio.sleep(0.6)
                        if dedup_key not in self.recent_role_events or (time.time() - self.recent_role_events[dedup_key]) >= 8:
                            mod_user = None
                            audit_reason = None
                            if guild.me.guild_permissions.view_audit_log:
                                try:
                                    async for entry in guild.audit_logs(limit=4, action=discord.AuditLogAction.member_role_update):
                                        if entry.target and entry.target.id == after.id:
                                            if abs((datetime.now(timezone.utc) - entry.created_at).total_seconds()) < 10:
                                                mod_user = entry.user
                                                audit_reason = entry.reason
                                                break
                                except Exception as e:
                                    logger.debug("Failed querying audit log for member_role_update: %s", e)

                            self.recent_role_events[dedup_key] = time.time()
                            await self._send_role_change_log(role_ch, after, added, removed, mod_user, audit_reason)

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

    @commands.Cog.listener()
    async def on_stage_instance_create(self, stage_instance: discord.StageInstance):
        guild = stage_instance.guild
        if not guild:
            return
        stage_ch = self._get_target_channel(guild, "stage") or self._get_target_channel(guild, "channel")
        if not stage_ch:
            return
        embed = discord.Embed(
            title="🎭 Stage Opened / Started",
            color=discord.Color.green(),
            description=f"Stage opened in **{stage_instance.channel.mention}**",
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Topic", value=stage_instance.topic, inline=False)
        embed.add_field(name="Channel", value=f"{stage_instance.channel.mention} (`{stage_instance.channel.id}`)", inline=True)
        embed.add_field(name="Privacy", value=str(stage_instance.privacy_level).title(), inline=True)
        try:
            await stage_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_stage_instance_delete(self, stage_instance: discord.StageInstance):
        guild = stage_instance.guild
        if not guild:
            return
        stage_ch = self._get_target_channel(guild, "stage") or self._get_target_channel(guild, "channel")
        if not stage_ch:
            return
        embed = discord.Embed(
            title="🛑 Stage Closed / Ended",
            color=discord.Color.red(),
            description=f"Stage ended in **{stage_instance.channel.mention}**",
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Topic", value=stage_instance.topic, inline=False)
        try:
            await stage_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_stage_instance_update(self, before: discord.StageInstance, after: discord.StageInstance):
        guild = after.guild
        if not guild:
            return
        stage_ch = self._get_target_channel(guild, "stage") or self._get_target_channel(guild, "channel")
        if not stage_ch:
            return
        changes = []
        if before.topic != after.topic:
            changes.append(f"**Topic:** `{before.topic}` ➔ `{after.topic}`")
        if before.privacy_level != after.privacy_level:
            changes.append(f"**Privacy:** `{before.privacy_level}` ➔ `{after.privacy_level}`")
        if not changes:
            return
        embed = discord.Embed(
            title="📝 Stage Updated",
            color=discord.Color.gold(),
            description=f"Stage in **{after.channel.mention}** was updated:\n" + "\n".join(changes),
            timestamp=datetime.now(timezone.utc)
        )
        try:
            await stage_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_scheduled_event_create(self, event: discord.ScheduledEvent):
        guild = event.guild
        if not guild:
            return
        event_ch = self._get_target_channel(guild, "event") or self._get_target_channel(guild, "server")
        if not event_ch:
            return
        embed = discord.Embed(
            title="📅 Scheduled Event Created",
            color=discord.Color.green(),
            description=f"**[{event.name}]({event.url})** was created.",
            timestamp=datetime.now(timezone.utc)
        )
        if event.description:
            embed.add_field(name="Description", value=event.description[:500], inline=False)
        creator_str = event.creator.mention if event.creator else "*Unknown*"
        embed.add_field(name="Organizer", value=creator_str, inline=True)
        if event.start_time:
            embed.add_field(name="Start Time", value=discord.utils.format_dt(event.start_time, "F"), inline=True)
        if event.channel:
            embed.add_field(name="Location", value=event.channel.mention, inline=True)
        elif event.location:
            embed.add_field(name="Location", value=event.location, inline=True)
        try:
            await event_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_scheduled_event_delete(self, event: discord.ScheduledEvent):
        guild = event.guild
        if not guild:
            return
        event_ch = self._get_target_channel(guild, "event") or self._get_target_channel(guild, "server")
        if not event_ch:
            return
        embed = discord.Embed(
            title="🗑️ Scheduled Event Canceled / Deleted",
            color=discord.Color.red(),
            description=f"Event **{event.name}** was deleted or canceled.",
            timestamp=datetime.now(timezone.utc)
        )
        try:
            await event_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_scheduled_event_update(self, before: discord.ScheduledEvent, after: discord.ScheduledEvent):
        guild = after.guild
        if not guild:
            return
        event_ch = self._get_target_channel(guild, "event") or self._get_target_channel(guild, "server")
        if not event_ch:
            return
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** `{before.name}` ➔ `{after.name}`")
        if before.description != after.description:
            changes.append("**Description updated**")
        if before.status != after.status:
            changes.append(f"**Status:** `{str(before.status).title()}` ➔ `{str(after.status).title()}`")
        if before.start_time != after.start_time and after.start_time:
            changes.append(f"**Start Time:** {discord.utils.format_dt(after.start_time, 'R')}")
        if not changes:
            return
        embed = discord.Embed(
            title="📅 Scheduled Event Updated",
            color=discord.Color.blue(),
            description=f"**[{after.name}]({after.url})** was updated:\n" + "\n".join(changes),
            timestamp=datetime.now(timezone.utc)
        )
        try:
            await event_ch.send(embed=embed)
        except Exception:
            pass

    @commands.Cog.listener()
    async def on_guild_emojis_update(self, guild: discord.Guild, before: Sequence[discord.Emoji], after: Sequence[discord.Emoji]):
        emoji_ch = self._get_target_channel(guild, "emoji") or self._get_target_channel(guild, "server")
        if not emoji_ch:
            return
        before_set = {e.id: e for e in before}
        after_set = {e.id: e for e in after}
        added = [e for eid, e in after_set.items() if eid not in before_set]
        removed = [e for eid, e in before_set.items() if eid not in after_set]

        embed = None
        now_ts = datetime.now(timezone.utc)
        if added:
            embed = discord.Embed(title="😃 Server Emoji(s) Added", color=discord.Color.green(), timestamp=now_ts)
            embed.description = " ".join([f"<:{e.name}:{e.id}> (`:{e.name}:`)" if not e.animated else f"<a:{e.name}:{e.id}> (`:{e.name}:`)" for e in added])
        elif removed:
            embed = discord.Embed(title="🗑️ Server Emoji(s) Removed", color=discord.Color.red(), timestamp=now_ts)
            embed.description = ", ".join([f"`:{e.name}:`" for e in removed])
        else:
            renamed = []
            for eid, e_after in after_set.items():
                e_before = before_set.get(eid)
                if e_before and e_before.name != e_after.name:
                    renamed.append(f"`:{e_before.name}:` ➔ `:{e_after.name}:`")
            if renamed:
                embed = discord.Embed(title="✏️ Server Emoji(s) Renamed", color=discord.Color.gold(), timestamp=now_ts)
                embed.description = "\n".join(renamed)

        if embed:
            try:
                await emoji_ch.send(embed=embed)
            except Exception:
                pass

    @commands.Cog.listener()
    async def on_guild_stickers_update(self, guild: discord.Guild, before: Sequence[discord.GuildSticker], after: Sequence[discord.GuildSticker]):
        emoji_ch = self._get_target_channel(guild, "emoji") or self._get_target_channel(guild, "server")
        if not emoji_ch:
            return
        before_set = {s.id: s for s in before}
        after_set = {s.id: s for s in after}
        added = [s for sid, s in after_set.items() if sid not in before_set]
        removed = [s for sid, s in before_set.items() if sid not in after_set]
        embed = None
        now_ts = datetime.now(timezone.utc)
        if added:
            embed = discord.Embed(title="🏷️ Sticker(s) Added", color=discord.Color.green(), timestamp=now_ts)
            embed.description = ", ".join([f"**{s.name}**" for s in added])
        elif removed:
            embed = discord.Embed(title="🗑️ Sticker(s) Removed", color=discord.Color.red(), timestamp=now_ts)
            embed.description = ", ".join([f"**{s.name}**" for s in removed])
        if embed:
            try:
                await emoji_ch.send(embed=embed)
            except Exception:
                pass

async def setup(bot: commands.Bot):
    await bot.add_cog(LoggingSystem(bot))

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

logger = logging.getLogger("security_bot.logging_system")

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

        log_channel = self._get_target_channel(message.guild, "chat")
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

        log_channel = self._get_target_channel(before.guild, "chat")
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
        log_channel = self._get_target_channel(guild, "voice")
        if not log_channel:
            return

        embed = None
        now_ts = datetime.now(timezone.utc)

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
                title=f"🎙️ Voice State Updated: {state_desc}",
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
                await log_channel.send(embed=embed)
            except Exception as e:
                logger.debug("Failed posting voice log: %s", e)

    # ==========================================
    # 3. MEMBER JOIN & LEAVE LOGS
    # ==========================================
    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        guild = member.guild
        log_channel = self._get_target_channel(guild, "member")
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
        log_channel = self._get_target_channel(guild, "member")
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

async def setup(bot: commands.Bot):
    await bot.add_cog(LoggingSystem(bot))

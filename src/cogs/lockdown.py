"""Server Lockdown Cog.
Provides safe, time-bounded, auto-expiring emergency lockdown that can be reversed at any time.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import discord
from discord import app_commands
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.lockdown")

class ServerLockdown(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # guild_id -> asyncio.Task for auto-expiration countdown
        self.lockdown_tasks: Dict[int, asyncio.Task] = {}
        # guild_id -> {channel_id: previous_send_messages_overwrite}
        self.previous_overwrites: Dict[int, Dict[int, Optional[bool]]] = {}
        # guild_id -> expiration datetime
        self.lockdown_expiry: Dict[int, datetime] = {}

    def is_locked(self, guild_id: int) -> bool:
        return guild_id in self.previous_overwrites and bool(self.previous_overwrites[guild_id])

    async def apply_lockdown(
        self,
        guild: discord.Guild,
        duration_minutes: int,
        reason: str,
        moderator: Optional[discord.Member] = None
    ) -> Tuple[bool, str]:
        """Locks down public channels by disabling @everyone Send Messages with auto-expiration."""
        if self.is_locked(guild.id):
            return False, "Server is already under an active lockdown."

        everyone_role = guild.default_role
        saved_overwrites: Dict[int, Optional[bool]] = {}
        locked_channels_count = 0

        cfg = bot_config.lockdown
        affected_channel_ids = cfg.get("affected_channels", [])

        for channel in guild.text_channels:
            if affected_channel_ids and channel.id not in affected_channel_ids:
                continue

            # Don't lock mod log or staff channels if bypassed by owner
            if bot_config.is_bypassed(guild, guild.me, channel):
                continue

            current_overwrite = channel.overwrites_for(everyone_role)
            saved_overwrites[channel.id] = current_overwrite.send_messages

            # Set send_messages to False for @everyone
            try:
                new_overwrite = discord.PermissionOverwrite.from_pair(
                    current_overwrite.pair()[0],
                    current_overwrite.pair()[1]
                )
                new_overwrite.send_messages = False
                await channel.set_permissions(everyone_role, overwrite=new_overwrite, reason=f"Lockdown by {moderator or 'Security Bot'}: {reason}")
                locked_channels_count += 1
            except discord.Forbidden:
                logger.warning("Bot lacks permission to modify overwrites in #%s", channel.name)
            except Exception as e:
                logger.error("Failed locking channel #%s: %s", channel.name, e)

        self.previous_overwrites[guild.id] = saved_overwrites
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        self.lockdown_expiry[guild.id] = expiry_time

        # Start background timer for automatic expiration
        task = asyncio.create_task(self._auto_expire_timer(guild.id, duration_minutes * 60))
        self.lockdown_tasks[guild.id] = task

        # Record to audit log
        await db.log_incident(
            guild_id=guild.id,
            user_id=moderator.id if moderator else 0,
            username=str(moderator) if moderator else "System Automated",
            rule_triggered="Emergency Server Lockdown",
            confidence="HIGH (Manual/Auto Defense)",
            raw_evidence=f"Duration: {duration_minutes}m | Reason: {reason} | Channels: {locked_channels_count}",
            action_taken=f"Locked {locked_channels_count} channels for {duration_minutes}m",
            moderator_id=moderator.id if moderator else None
        )

        return True, f"Locked down {locked_channels_count} channels for {duration_minutes} minutes."

    async def lift_lockdown(self, guild: discord.Guild, moderator: Optional[discord.Member] = None) -> Tuple[bool, str]:
        """Restores channel permissions to their exact state prior to lockdown."""
        if not self.is_locked(guild.id):
            return False, "Server is not currently in lockdown mode."

        # Cancel auto-expiry timer if running
        if guild.id in self.lockdown_tasks:
            self.lockdown_tasks[guild.id].cancel()
            del self.lockdown_tasks[guild.id]

        saved_overwrites = self.previous_overwrites.pop(guild.id, {})
        self.lockdown_expiry.pop(guild.id, None)
        everyone_role = guild.default_role
        restored_count = 0

        for channel_id, prev_val in saved_overwrites.items():
            channel = guild.get_channel(channel_id)
            if not isinstance(channel, discord.TextChannel):
                continue

            try:
                current_overwrite = channel.overwrites_for(everyone_role)
                current_overwrite.send_messages = prev_val
                if current_overwrite.is_empty():
                    await channel.set_permissions(everyone_role, overwrite=None, reason="Lockdown lifted")
                else:
                    await channel.set_permissions(everyone_role, overwrite=current_overwrite, reason="Lockdown lifted")
                restored_count += 1
            except Exception as e:
                logger.error("Failed restoring permissions in channel %s: %s", channel_id, e)

        # Record to audit log
        await db.log_incident(
            guild_id=guild.id,
            user_id=moderator.id if moderator else 0,
            username=str(moderator) if moderator else "System Auto-Expiry",
            rule_triggered="Lockdown Lifted",
            confidence="HIGH",
            raw_evidence=f"Restored {restored_count} channels",
            action_taken="Lockdown Reversed",
            moderator_id=moderator.id if moderator else None
        )

        return True, f"Lockdown lifted. Restored permissions across {restored_count} channels."

    async def _auto_expire_timer(self, guild_id: int, delay_seconds: int):
        try:
            await asyncio.sleep(delay_seconds)
            guild = self.bot.get_guild(guild_id)
            if guild and self.is_locked(guild_id):
                logger.info("Lockdown duration expired for guild %s. Lifting automatically.", guild.name)
                success, msg = await self.lift_lockdown(guild, moderator=None)
                
                # Notify mod alert channel
                alert_ch_id = bot_config.alert_channel_id
                if alert_ch_id:
                    ch = self.bot.get_channel(alert_ch_id)
                    if ch:
                        embed = discord.Embed(
                            title="🔓 Server Lockdown Auto-Expired",
                            description=f"The scheduled lockdown has concluded.\n{msg}",
                            color=discord.Color.green(),
                            timestamp=datetime.now(timezone.utc)
                        )
                        await ch.send(embed=embed)
        except asyncio.CancelledError:
            pass

async def setup(bot: commands.Bot):
    await bot.add_cog(ServerLockdown(bot))

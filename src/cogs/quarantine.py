"""Quarantine System Cog for Karuppu / Antigravity Security Bot.
Provides indefinite member isolation:
- /quarantine: Strips all roles, backs them up, applies Quarantine role, blocks all channel & voice access.
- /quarantine_setup: Asks for role, creates quarantine category with a text channel and voice channel, and isolates all other server categories.
- /quarantine_view: Shows who all are currently quarantined in the server.
- /unquarantine: Removes the quarantine role and restores all original backed-up roles.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union
import discord
from discord import app_commands
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.quarantine")

class QuarantineSystem(commands.Cog, name="quarantine"):
    """Server Member Quarantine & Isolation Engine."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # ==========================================
    # PERMISSION & HIERARCHY CHECKS
    # ==========================================

    def _is_admin_or_owner(self, user: Union[discord.Member, discord.User], guild: discord.Guild) -> bool:
        """Only Server Owner, Administrators, and authorized Manage Guild staff can manage quarantine."""
        if user.id == guild.owner_id:
            return True
        if bot_config.is_bot_owner(user.id):
            return True
        if isinstance(user, discord.Member):
            if user.guild_permissions.administrator:
                return True
            if user.guild_permissions.manage_guild:
                return True
        return False

    def _can_moderate_target(self, moderator: discord.Member, target: discord.Member, guild: discord.Guild) -> Tuple[bool, str]:
        """Validates that the moderator has authority to quarantine the target member."""
        if target.id == moderator.id:
            return False, "❌ You cannot quarantine yourself."
        if target.id == guild.owner_id:
            return False, "❌ You cannot quarantine the Server Owner."
        if target.id == guild.me.id:
            return False, "❌ You cannot quarantine the security bot."
        if target.bot and target.id == self.bot.user.id:
            return False, "❌ Cannot quarantine the bot."

        # Server owner bypasses role hierarchy checks
        if moderator.id != guild.owner_id and not bot_config.is_bot_owner(moderator.id):
            # Target is an administrator
            if target.guild_permissions.administrator:
                return False, "❌ You cannot quarantine another Administrator. Only the Server Owner can quarantine admins."

            # Moderator top role must be strictly higher than target top role
            if target.top_role >= moderator.top_role:
                return False, f"❌ You cannot quarantine {target.mention} because their highest role is equal to or higher than yours."

        # Bot permissions and hierarchy checks
        me = guild.me
        if not me.guild_permissions.manage_roles:
            return False, "❌ Bot lacks the **'Manage Roles'** permission in this server."

        if target.top_role >= me.top_role:
            return False, f"❌ Bot cannot quarantine {target.mention} because their highest role is equal to or higher than the bot's highest role. Move the bot's role higher in Server Settings."

        return True, ""

    # ==========================================
    # ROLE & CATEGORY RESOLVERS
    # ==========================================

    async def get_or_create_quarantine_role(self, guild: discord.Guild) -> Optional[discord.Role]:
        """Finds existing Quarantine role (case-insensitive) or creates one with no channel view perms."""
        # 1. Check guild settings cache / database
        settings = bot_config.guild_settings_cache.get(guild.id, {})
        role_id = settings.get("quarantine_role_id")
        if role_id:
            role = guild.get_role(role_id)
            if role:
                return role

        # 2. Search existing guild roles by name
        target_names = ("quarantine", "quarantined", "isolated", "isolation")
        cfg_name = bot_config.raid_detector.get("quarantine_role_name", "Quarantined").lower().strip()

        for role in guild.roles:
            rname = role.name.lower().strip()
            if rname in target_names or rname == cfg_name:
                await db.set_quarantine_role(guild.id, role.id)
                settings["quarantine_role_id"] = role.id
                bot_config.guild_settings_cache[guild.id] = settings
                return role

        # 3. Create Quarantine role if bot has Manage Roles
        if guild.me.guild_permissions.manage_roles:
            try:
                role = await guild.create_role(
                    name="Quarantined",
                    color=discord.Color.from_rgb(47, 49, 54),
                    permissions=discord.Permissions.none(),
                    reason="Auto-created quarantine role for server security isolation"
                )
                await db.set_quarantine_role(guild.id, role.id)
                settings["quarantine_role_id"] = role.id
                bot_config.guild_settings_cache[guild.id] = settings
                logger.info("Auto-created Quarantine role '%s' (%d) in '%s'", role.name, role.id, guild.name)
                return role
            except Exception as e:
                logger.warning("Could not auto-create quarantine role in '%s': %s", guild.name, e)

        return None

    async def get_or_create_quarantine_category(
        self,
        guild: discord.Guild,
        quarantine_role: Optional[discord.Role] = None
    ) -> Optional[discord.CategoryChannel]:
        """Finds or creates the designated Quarantine Category that quarantined members are restricted to."""
        settings = bot_config.guild_settings_cache.get(guild.id, {})
        cat_id = settings.get("quarantine_category_id")
        if cat_id:
            cat = guild.get_channel(cat_id)
            if isinstance(cat, discord.CategoryChannel):
                return cat

        # Search existing categories by name
        target_names = ("quarantine", "isolation", "quarantined", "quarantine zone", "holding cell")
        for cat in guild.categories:
            cname = cat.name.lower().strip()
            if any(t in cname for t in target_names):
                await db.set_quarantine_category(guild.id, cat.id)
                settings["quarantine_category_id"] = cat.id
                bot_config.guild_settings_cache[guild.id] = settings
                return cat

        # Auto-create Quarantine Category if bot has Manage Channels
        if guild.me.guild_permissions.manage_channels:
            try:
                overwrites = {
                    guild.default_role: discord.PermissionOverwrite(view_channel=False, connect=False),
                    guild.me: discord.PermissionOverwrite(view_channel=True, manage_channels=True, manage_permissions=True, send_messages=True, connect=True)
                }
                if quarantine_role:
                    overwrites[quarantine_role] = discord.PermissionOverwrite(
                        view_channel=True,
                        send_messages=True,
                        read_message_history=True,
                        connect=True,
                        speak=True
                    )

                cat = await guild.create_category(
                    name="🔒 Quarantine Zone",
                    overwrites=overwrites,
                    reason="Auto-created quarantine holding category"
                )

                # Create text and voice channels inside it
                await guild.create_text_channel(
                    name="quarantine-chat",
                    category=cat,
                    topic="Private holding area for quarantined members.",
                    reason="Auto-created quarantine text channel"
                )
                await guild.create_voice_channel(
                    name="quarantine-voice",
                    category=cat,
                    reason="Auto-created quarantine voice channel"
                )

                await db.set_quarantine_category(guild.id, cat.id)
                settings["quarantine_category_id"] = cat.id
                bot_config.guild_settings_cache[guild.id] = settings
                logger.info("Auto-created Quarantine Category '%s' (%d) in '%s'", cat.name, cat.id, guild.name)
                return cat
            except Exception as e:
                logger.warning("Could not auto-create quarantine category in '%s': %s", guild.name, e)

        return None

    # ==========================================
    # OVERWRITE SYNC ENGINE: HIDE ALL OTHER CHANNELS & CATEGORIES
    # ==========================================

    async def sync_quarantine_overwrites(
        self,
        guild: discord.Guild,
        quarantine_role: discord.Role,
        quarantine_category: Optional[discord.CategoryChannel] = None
    ) -> Tuple[int, int, List[str]]:
        """Enforces full server isolation:
        - Sets view_channel=True on the Quarantine Category for the Quarantine role.
        - Sets view_channel=False on EVERY OTHER category and orphan channel for the Quarantine role.
        """
        if not guild.me.guild_permissions.manage_channels:
            return 0, 0, ["Bot lacks Manage Channels permission."]

        categories_hidden = 0
        channels_hidden = 0
        errors = []

        # 1. Enforce Quarantine Category permissions (visible only to quarantined members and staff)
        if quarantine_category:
            try:
                q_ow = quarantine_category.overwrites.get(quarantine_role)
                new_q_ow = discord.PermissionOverwrite.from_pair(q_ow.pair()[0], q_ow.pair()[1]) if q_ow else discord.PermissionOverwrite()
                new_q_ow.view_channel = True
                new_q_ow.send_messages = True
                new_q_ow.read_message_history = True
                new_q_ow.connect = True
                new_q_ow.speak = True
                await quarantine_category.set_permissions(quarantine_role, overwrite=new_q_ow, reason="Quarantine isolation: Allow quarantine category")

                # Hide quarantine category from public (@everyone)
                ev_ow = quarantine_category.overwrites.get(guild.default_role)
                new_ev_ow = discord.PermissionOverwrite.from_pair(ev_ow.pair()[0], ev_ow.pair()[1]) if ev_ow else discord.PermissionOverwrite()
                new_ev_ow.view_channel = False
                new_ev_ow.connect = False
                await quarantine_category.set_permissions(guild.default_role, overwrite=new_ev_ow, reason="Quarantine isolation: Hide from public")

                # Ensure child channels in quarantine category allow quarantine role
                for ch in quarantine_category.channels:
                    try:
                        ch_ow = ch.overwrites.get(quarantine_role)
                        if ch_ow and (ch_ow.view_channel is False or ch_ow.connect is False):
                            ch_ow.view_channel = True
                            if isinstance(ch, discord.VoiceChannel):
                                ch_ow.connect = True
                                ch_ow.speak = True
                            else:
                                ch_ow.send_messages = True
                            await ch.set_permissions(quarantine_role, overwrite=ch_ow, reason="Quarantine child channel access")
                    except Exception:
                        pass
            except Exception as e:
                errors.append(f"Quarantine Category: {e}")

        # 2. Block Quarantine role from viewing every other category in the server
        for cat in guild.categories:
            if quarantine_category and cat.id == quarantine_category.id:
                continue

            current_ow = cat.overwrites.get(quarantine_role)
            if current_ow is None or current_ow.view_channel is not False or current_ow.connect is not False:
                new_ow = discord.PermissionOverwrite.from_pair(current_ow.pair()[0], current_ow.pair()[1]) if current_ow else discord.PermissionOverwrite()
                new_ow.view_channel = False
                new_ow.connect = False
                try:
                    await cat.set_permissions(quarantine_role, overwrite=new_ow, reason="Quarantine isolation: Hide category from quarantined users")
                    categories_hidden += 1
                except Exception as e:
                    errors.append(f"Category '{cat.name}': {e}")

        # 3. Block Quarantine role from viewing orphaned channels (channels not in any category)
        for ch in guild.channels:
            if isinstance(ch, discord.CategoryChannel):
                continue
            if ch.category is None:
                current_ow = ch.overwrites.get(quarantine_role)
                if current_ow is None or current_ow.view_channel is not False or current_ow.connect is not False:
                    new_ow = discord.PermissionOverwrite.from_pair(current_ow.pair()[0], current_ow.pair()[1]) if current_ow else discord.PermissionOverwrite()
                    new_ow.view_channel = False
                    new_ow.connect = False
                    try:
                        await ch.set_permissions(quarantine_role, overwrite=new_ow, reason="Quarantine isolation: Hide uncategorized channel")
                        channels_hidden += 1
                    except Exception as e:
                        errors.append(f"Channel '#{ch.name}': {e}")

        logger.info(
            "Quarantine sync in '%s': %d categories hidden, %d orphaned channels hidden",
            guild.name, categories_hidden, channels_hidden
        )
        return categories_hidden, channels_hidden, errors

    # ==========================================
    # CORE QUARANTINE LOGIC
    # ==========================================

    async def quarantine_member(
        self,
        guild: discord.Guild,
        target: discord.Member,
        moderator: Union[discord.Member, discord.User],
        reason: str = "Quarantined by staff"
    ) -> Tuple[bool, str, Optional[discord.Embed]]:
        """Quarantines a member:
        - Resolves Quarantine role and Quarantine category.
        - Synchronizes server-wide channel isolation (denies view on all other categories).
        - Backs up existing roles in database.
        - Strips all roles and applies Quarantine role.
        - Disconnects from voice channels.
        """
        if bot_config.is_quarantined(guild.id, target.id):
            entry = bot_config.get_quarantine(guild.id, target.id) or {}
            q_time = entry.get("quarantined_at", "Unknown")
            return False, f"⚠️ {target.mention} is already quarantined (since `{q_time}`).", None

        # Resolve quarantine role
        quarantine_role = await self.get_or_create_quarantine_role(guild)
        if not quarantine_role:
            return False, "❌ No **Quarantine** role found or could be created. Please run `/quarantine_setup` first.", None

        if quarantine_role >= guild.me.top_role:
            return False, f"❌ Bot's highest role is lower than {quarantine_role.mention}. Please move the bot's role above `{quarantine_role.name}` in Server Settings.", None

        # Resolve quarantine category and sync channel overwrites
        quarantine_category = await self.get_or_create_quarantine_category(guild, quarantine_role)
        await self.sync_quarantine_overwrites(guild, quarantine_role, quarantine_category)

        # 1. Back up existing roles (excluding @everyone, quarantine_role)
        saved_roles = [r for r in target.roles if r != guild.default_role and r != quarantine_role]
        saved_role_ids = [r.id for r in saved_roles]

        # 2. Check and temporarily suppress member-specific channel overrides that might give view access
        suppressed_overwrites = []
        if guild.me.guild_permissions.manage_channels:
            for ch in guild.channels:
                if quarantine_category and getattr(ch, "category_id", None) == quarantine_category.id:
                    continue  # Keep access inside quarantine category
                ow = ch.overwrites.get(target)
                if ow and ow.view_channel is True:
                    suppressed_overwrites.append(ch.id)
                    try:
                        ow.view_channel = False
                        await ch.set_permissions(target, overwrite=ow, reason=f"Quarantine channel isolation by {moderator}")
                    except Exception:
                        pass

        # 3. Strip all removable roles and assign Quarantine role
        # Managed roles (e.g. Nitro Booster) and roles >= bot top role cannot be removed
        roles_to_keep = [r for r in target.roles if (r.managed or r >= guild.me.top_role) and r != guild.default_role]
        new_roles = [guild.default_role, quarantine_role] + [r for r in roles_to_keep if r != quarantine_role]

        try:
            await target.edit(roles=new_roles, reason=f"Quarantine enforced by {moderator}: {reason}")
        except discord.Forbidden:
            return False, "❌ Bot lacks permission to modify roles for this member. Check role hierarchy.", None
        except Exception as e:
            return False, f"❌ Failed updating member roles: {e}", None

        # 4. Disconnect from voice if currently in a voice channel
        if target.voice and target.voice.channel and guild.me.guild_permissions.move_members:
            try:
                await target.move_to(None, reason=f"Quarantine enforced by {moderator}")
            except Exception:
                pass

        # 5. Save to database and in-memory cache
        overwrites_json = json.dumps(suppressed_overwrites) if suppressed_overwrites else None
        await db.save_quarantine(
            guild_id=guild.id,
            user_id=target.id,
            saved_role_ids=saved_role_ids,
            quarantined_by=moderator.id,
            reason=reason,
            overwrites_backup=overwrites_json
        )
        bot_config.quarantine_cache[(guild.id, target.id)] = {
            "guild_id": guild.id,
            "user_id": target.id,
            "saved_role_ids": saved_role_ids,
            "quarantined_by": moderator.id,
            "reason": reason,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "overwrites_backup": overwrites_json
        }

        # 6. Audit logging
        await db.log_incident(
            guild_id=guild.id,
            user_id=target.id,
            username=str(target),
            rule_triggered="Member Quarantine",
            confidence="HIGH (Admin Enforcement)",
            raw_evidence=f"Roles stripped ({len(saved_role_ids)}): {', '.join([r.name for r in saved_roles])} | Reason: {reason}",
            action_taken=f"Quarantined by {moderator}",
            moderator_id=moderator.id
        )

        # 7. DM the quarantined user
        cat_text = f" You can view and speak only inside the **{quarantine_category.name}** category." if quarantine_category else ""
        try:
            dm_embed = discord.Embed(
                title=f"🛡️ Quarantined in {guild.name}",
                color=discord.Color.red(),
                description=(
                    f"You have been placed under **Quarantine** by server administration.\n\n"
                    f"**Reason:** {reason}\n"
                    f"**Status:** All your roles have been temporarily revoked.{cat_text}\n\n"
                    f"🔒 *This quarantine has no automatic timer. Only an Administrator or Server Owner can lift your quarantine.*"
                ),
                timestamp=datetime.now(timezone.utc)
            )
            dm_embed.set_footer(text=f"Enforced by {moderator}")
            await target.send(embed=dm_embed)
        except Exception:
            pass  # User has DMs disabled

        # 8. Dispatch rich embed to server log channels
        role_mentions = [r.mention for r in saved_roles[:15]]
        if len(saved_roles) > 15:
            role_mentions.append(f"...and {len(saved_roles) - 15} more")
        roles_display = ", ".join(role_mentions) if role_mentions else "*No prior roles*"
        cat_display = f"`{quarantine_category.name}`" if quarantine_category else "*Not configured*"

        log_embed = discord.Embed(
            title="🔒 Member Quarantined (Indefinite Isolation)",
            color=discord.Color.red(),
            description=(
                f"**Target Member:** {target.mention} (`{target.id}`)\n"
                f"**Moderator:** {moderator.mention} (`{moderator.id}`)\n"
                f"**Reason:** {reason}\n\n"
                f"🛡️ **Quarantine Role:** {quarantine_role.mention}\n"
                f"📁 **Allowed Category:** {cat_display} *(All other categories hidden)*\n"
                f"📦 **Roles Backed Up & Stripped ({len(saved_role_ids)}):**\n{roles_display}\n\n"
                f"⏳ **Duration:** Indefinite (Requires manual `/unquarantine` by Admin/Owner)"
            ),
            timestamp=datetime.now(timezone.utc)
        )
        log_embed.set_thumbnail(url=target.display_avatar.url)
        log_embed.set_footer(text="Karuppu Quarantine Engine • Full server isolation active")

        await self._dispatch_to_log_channels(guild, log_embed)

        return True, f"Successfully quarantined {target.mention}.", log_embed

    async def unquarantine_member(
        self,
        guild: discord.Guild,
        user_id: int,
        moderator: Union[discord.Member, discord.User],
        reason: str = "Quarantine lifted by staff"
    ) -> Tuple[bool, str, Optional[discord.Embed]]:
        """Lifts quarantine from a member: restores all backed-up roles and channel permissions."""
        record = await db.get_quarantine(guild.id, user_id)
        if not record and not bot_config.is_quarantined(guild.id, user_id):
            return False, "⚠️ This user is not currently in quarantine.", None

        saved_role_ids = record.get("saved_role_ids", []) if record else []
        overwrites_backup = record.get("overwrites_backup") if record else None

        target = guild.get_member(user_id)
        quarantine_role = await self.get_or_create_quarantine_role(guild)

        restored_roles = []
        restored_names = []

        if target:
            # 1. Resolve roles to restore
            for rid in saved_role_ids:
                role = guild.get_role(rid)
                if role and not role.managed and role < guild.me.top_role and role != quarantine_role:
                    restored_roles.append(role)
                    restored_names.append(role.name)

            # 2. Re-apply restored roles and remove quarantine role
            new_roles = [r for r in target.roles if (not quarantine_role or r != quarantine_role) and r != guild.default_role]
            for r in restored_roles:
                if r not in new_roles:
                    new_roles.append(r)

            try:
                await target.edit(roles=new_roles, reason=f"Quarantine lifted by {moderator}: {reason}")
            except discord.Forbidden:
                return False, "❌ Bot lacks permission to restore roles to this member. Check role hierarchy.", None
            except Exception as e:
                return False, f"❌ Failed restoring member roles: {e}", None

            # 3. Restore any suppressed channel overrides
            if overwrites_backup and guild.me.guild_permissions.manage_channels:
                try:
                    ch_ids = json.loads(overwrites_backup)
                    for cid in ch_ids:
                        ch = guild.get_channel(cid)
                        if ch:
                            ow = ch.overwrites.get(target)
                            if ow:
                                ow.view_channel = True
                                await ch.set_permissions(target, overwrite=ow, reason="Restored quarantine channel view access")
                except Exception:
                    pass

            # 4. DM the user
            try:
                dm_embed = discord.Embed(
                    title=f"✅ Quarantine Lifted in {guild.name}",
                    color=discord.Color.green(),
                    description=(
                        f"Your **Quarantine** in **{guild.name}** has been lifted by {moderator.mention}.\n\n"
                        f"**Reason:** {reason}\n"
                        f"**Restored Roles ({len(restored_roles)}):** {', '.join(restored_names) if restored_names else 'None'}\n\n"
                        f"Your server access and visibility have been fully restored."
                    ),
                    timestamp=datetime.now(timezone.utc)
                )
                await target.send(embed=dm_embed)
            except Exception:
                pass

        # 5. Remove from database and cache
        await db.remove_quarantine(guild.id, user_id)
        bot_config.quarantine_cache.pop((guild.id, user_id), None)

        # 6. Audit logging
        await db.log_incident(
            guild_id=guild.id,
            user_id=user_id,
            username=str(target) if target else f"User ID {user_id}",
            rule_triggered="Quarantine Lifted",
            confidence="HIGH (Admin Action)",
            raw_evidence=f"Restored {len(restored_roles)} roles | Reason: {reason}",
            action_taken=f"Unquarantined by {moderator}",
            moderator_id=moderator.id
        )

        target_display = target.mention if target else f"<@{user_id}>"
        roles_display = ", ".join([r.mention for r in restored_roles[:15]]) if restored_roles else "*No roles to restore*"

        log_embed = discord.Embed(
            title="🔓 Member Quarantine Lifted",
            color=discord.Color.green(),
            description=(
                f"**Target Member:** {target_display} (`{user_id}`)\n"
                f"**Authorized Staff:** {moderator.mention} (`{moderator.id}`)\n"
                f"**Reason:** {reason}\n\n"
                f"📦 **Restored Roles ({len(restored_roles)}):**\n{roles_display}\n\n"
                f"✅ Member's full server visibility and roles have been restored."
            ),
            timestamp=datetime.now(timezone.utc)
        )
        if target:
            log_embed.set_thumbnail(url=target.display_avatar.url)
        log_embed.set_footer(text="Karuppu Quarantine Engine • Role restoration complete")

        await self._dispatch_to_log_channels(guild, log_embed)

        return True, f"Successfully lifted quarantine for {target_display}.", log_embed

    async def _dispatch_to_log_channels(self, guild: discord.Guild, embed: discord.Embed) -> None:
        """Sends the quarantine log embed to appropriate server log channels."""
        logging_cog = self.bot.get_cog("LoggingSystem")
        target_channel = None

        if logging_cog and hasattr(logging_cog, "_get_target_channel"):
            for cat in ("mod", "security", "member", "admin"):
                target_channel = logging_cog._get_target_channel(guild, cat)
                if target_channel:
                    break

        if not target_channel:
            target_channel = bot_config.get_alert_channel(guild)

        if target_channel and isinstance(target_channel, discord.TextChannel):
            try:
                await target_channel.send(embed=embed)
            except Exception as e:
                logger.warning("Could not dispatch quarantine log embed to #%s: %s", target_channel.name, e)

    # ==========================================
    # LISTENERS: REJOIN PERSISTENCE & VOICE LOCK
    # ==========================================

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        """Prevents quarantined members from evading quarantine by rejoining the server."""
        guild = member.guild
        if not bot_config.is_quarantined(guild.id, member.id):
            return

        logger.warning("Quarantined member %s (%d) rejoined '%s'. Re-enforcing quarantine...", member, member.id, guild.name)
        quarantine_role = await self.get_or_create_quarantine_role(guild)
        if not quarantine_role or quarantine_role >= guild.me.top_role:
            return

        quarantine_category = await self.get_or_create_quarantine_category(guild, quarantine_role)
        await self.sync_quarantine_overwrites(guild, quarantine_role, quarantine_category)

        try:
            roles_to_keep = [r for r in member.roles if (r.managed or r >= guild.me.top_role) and r != guild.default_role]
            new_roles = [guild.default_role, quarantine_role] + [r for r in roles_to_keep if r != quarantine_role]
            await member.edit(roles=new_roles, reason="Quarantine re-enforced on rejoin")

            alert_embed = discord.Embed(
                title="⚠️ Quarantined Member Rejoined",
                color=discord.Color.gold(),
                description=(
                    f"**Member:** {member.mention} (`{member.id}`)\n"
                    f"**Status:** Attempted to rejoin while under active quarantine.\n"
                    f"🛡️ **Action:** Quarantine role {quarantine_role.mention} was immediately re-applied and auto-roles removed."
                ),
                timestamp=datetime.now(timezone.utc)
            )
            alert_embed.set_thumbnail(url=member.display_avatar.url)
            alert_embed.set_footer(text="Karuppu Rejoin Shield")
            await self._dispatch_to_log_channels(guild, alert_embed)
        except Exception as e:
            logger.error("Failed re-enforcing quarantine on rejoin for %s: %s", member, e)

    @commands.Cog.listener()
    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        """Immediately disconnects quarantined members if they attempt to join voice channels outside quarantine category."""
        if not after.channel:
            return
        guild = member.guild
        if bot_config.is_quarantined(guild.id, member.id):
            settings = bot_config.guild_settings_cache.get(guild.id, {})
            cat_id = settings.get("quarantine_category_id")
            # If the voice channel is inside the quarantine category, allow them to speak there
            if cat_id and after.channel.category_id == cat_id:
                return

            if guild.me.guild_permissions.move_members:
                try:
                    await member.move_to(None, reason="Quarantined user voice connection blocked outside quarantine category")
                    logger.info("Blocked voice connection for quarantined user %s in '%s'", member, guild.name)
                except Exception:
                    pass

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        """Protects against unauthorized role grants while under quarantine."""
        guild = after.guild
        if not bot_config.is_quarantined(guild.id, after.id):
            return

        quarantine_role = await self.get_or_create_quarantine_role(guild)
        if not quarantine_role or quarantine_role >= guild.me.top_role:
            return

        added_roles = [r for r in after.roles if r not in before.roles and r != quarantine_role and r != guild.default_role and not r.managed]
        if added_roles and guild.me.guild_permissions.manage_roles:
            new_roles = [r for r in after.roles if r not in added_roles]
            if quarantine_role not in new_roles:
                new_roles.append(quarantine_role)
            try:
                await after.edit(roles=new_roles, reason="Unauthorized role grant stripped: Member is under Quarantine")
                logger.info("Stripped unauthorized roles %s from quarantined member %s", [r.name for r in added_roles], after)
            except Exception:
                pass

    # ==========================================
    # ONLY 4 QUARANTINE SLASH COMMANDS
    # ==========================================

    # 1. /quarantine
    @app_commands.command(
        name="quarantine",
        description="[Admins/Owner Only] Strip all roles and isolate a member indefinitely."
    )
    @app_commands.describe(
        member="The member to place into quarantine",
        reason="Reason for placing member in quarantine (optional)"
    )
    async def slash_quarantine(self, interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = "Quarantined by staff"):
        await interaction.response.defer(ephemeral=True)
        if not self._is_admin_or_owner(interaction.user, interaction.guild):
            await interaction.followup.send("❌ Only **Server Owners** and **Administrators** can quarantine members.", ephemeral=True)
            return

        can_mod, err = self._can_moderate_target(interaction.user, member, interaction.guild)
        if not can_mod:
            await interaction.followup.send(err, ephemeral=True)
            return

        success, msg, embed = await self.quarantine_member(interaction.guild, member, interaction.user, reason=reason)
        if success and embed:
            if interaction.guild.owner_id == member.id:
                embed.description += "\n\n*(Note: Discord always shows all channels to Server Owner. Test using 'View Server as Role')*"
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(msg, ephemeral=True)

    # 2. /quarantine_setup
    @app_commands.command(
        name="quarantine_setup",
        description="[Admins Only] Assigns quarantine role, creates quarantine category with text/voice channels & isolates server."
    )
    @app_commands.describe(
        role="The Quarantine role (will be given text and voice access to the new quarantine category)"
    )
    async def slash_quarantine_setup(
        self,
        interaction: discord.Interaction,
        role: discord.Role
    ):
        await interaction.response.defer(ephemeral=True)
        if not self._is_admin_or_owner(interaction.user, interaction.guild):
            await interaction.followup.send("❌ Administrator or Server Owner permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        me = guild.me
        if not me.guild_permissions.manage_channels or not me.guild_permissions.manage_roles:
            await interaction.followup.send("❌ Bot lacks **'Manage Channels'** or **'Manage Roles'** permissions.", ephemeral=True)
            return

        # Save role
        await db.set_quarantine_role(guild.id, role.id)
        settings = bot_config.guild_settings_cache.get(guild.id, {})
        settings["quarantine_role_id"] = role.id

        # 1. Base category overwrites
        cat_overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False, connect=False),
            me: discord.PermissionOverwrite(view_channel=True, manage_channels=True, manage_permissions=True, send_messages=True, connect=True),
            role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True, connect=True, speak=True)
        }

        # Find existing or create category
        category = None
        cat_id = settings.get("quarantine_category_id")
        if cat_id:
            ch = guild.get_channel(cat_id)
            if isinstance(ch, discord.CategoryChannel):
                category = ch

        if not category:
            for c in guild.categories:
                cname = c.name.lower().strip()
                if "quarantine" in cname or "isolation" in cname:
                    category = c
                    break

        if not category:
            category = await guild.create_category("🔒 Quarantine Zone", overwrites=cat_overwrites, reason=f"Quarantine setup by {interaction.user}")
        else:
            try:
                await category.set_permissions(guild.default_role, view_channel=False, connect=False, reason="Quarantine isolation")
                await category.set_permissions(role, view_channel=True, send_messages=True, read_message_history=True, connect=True, speak=True, reason="Quarantine role access")
                await category.set_permissions(me, view_channel=True, manage_channels=True, manage_permissions=True, send_messages=True, connect=True)
            except Exception:
                pass

        await db.set_quarantine_category(guild.id, category.id)
        settings["quarantine_category_id"] = category.id
        bot_config.guild_settings_cache[guild.id] = settings

        # 2. Create or find text channel
        text_ch = None
        for ch in category.text_channels:
            if "quarantine" in ch.name.lower() or "chat" in ch.name.lower():
                text_ch = ch
                break
        if not text_ch:
            text_ch = await guild.create_text_channel(
                name="quarantine-chat",
                category=category,
                topic="Private holding area for quarantined members.",
                reason=f"Quarantine setup by {interaction.user}"
            )

        # 3. Create or find voice channel
        voice_ch = None
        for vc in category.voice_channels:
            if "quarantine" in vc.name.lower() or "voice" in vc.name.lower() or "vc" in vc.name.lower():
                voice_ch = vc
                break
        if not voice_ch:
            voice_ch = await guild.create_voice_channel(
                name="quarantine-voice",
                category=category,
                reason=f"Quarantine setup by {interaction.user}"
            )

        # 4. Isolate server: hide all other categories and orphaned channels
        cats_h, chs_h, _ = await self.sync_quarantine_overwrites(guild, role, category)

        embed = discord.Embed(
            title="🛡️ Quarantine Setup Complete",
            color=discord.Color.green(),
            description=(
                f"**Quarantine Category & Channels Created & Isolated!**\n\n"
                f"🏷️ **Quarantine Role:** {role.mention} (`{role.id}`)\n"
                f"📁 **Quarantine Category:** `{category.name}` (`{category.id}`)\n"
                f"💬 **Text Channel:** {text_ch.mention}\n"
                f"🔊 **Voice Channel:** {voice_ch.mention}\n\n"
                f"🔒 **Server Isolation Enforced:**\n"
                f"• `{cats_h}` other server categories hidden from {role.mention}\n"
                f"• `{chs_h}` uncategorized channels hidden from {role.mention}\n\n"
                f"✅ **Guaranteed:** Quarantined members can **ONLY** view and speak in this Quarantine category. All other channels in the server are completely invisible to them!"
            ),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text="Karuppu Quarantine Engine • Category & Channels Ready")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # 3. /quarantine_view
    @app_commands.command(
        name="quarantine_view",
        description="[Admins/Owner Only] View all members currently in quarantine."
    )
    async def slash_quarantine_view(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if not self._is_admin_or_owner(interaction.user, interaction.guild):
            await interaction.followup.send("❌ Administrator or Server Owner permissions required.", ephemeral=True)
            return

        records = await db.get_all_quarantined(interaction.guild.id)
        if not records:
            await interaction.followup.send("✅ There are currently **no members in quarantine** in this server.", ephemeral=True)
            return

        embed = discord.Embed(
            title=f"🔒 Quarantined Members in {interaction.guild.name} ({len(records)})",
            color=discord.Color.dark_red(),
            description="Members below have had all roles stripped and channel visibility revoked until manually released.\n",
            timestamp=datetime.now(timezone.utc)
        )

        for rec in records[:25]:
            uid = rec["user_id"]
            mem = interaction.guild.get_member(uid)
            display = f"{mem.mention} (`{uid}`)" if mem else f"User ID `{uid}` *(Left Server)*"
            roles_count = len(rec.get("saved_role_ids", []))
            mod = f"<@{rec['quarantined_by']}>"
            q_time = rec.get("quarantined_at", "Unknown")[:19].replace("T", " ")
            reason = rec.get("reason", "No reason provided")

            embed.add_field(
                name=f"👤 {display}",
                value=(
                    f"• **Reason:** {reason}\n"
                    f"• **Staff:** {mod}\n"
                    f"• **Backed-up Roles:** `{roles_count}` roles\n"
                    f"• **Quarantined At:** `{q_time} UTC`"
                ),
                inline=False
            )

        embed.set_footer(text="Use /unquarantine to release a member and restore their roles.")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # 4. /unquarantine
    @app_commands.command(
        name="unquarantine",
        description="[Admins/Owner Only] Lift quarantine and restore all original roles to a user."
    )
    @app_commands.describe(
        user="The member or user to release from quarantine",
        reason="Reason for lifting quarantine (optional)"
    )
    async def slash_unquarantine(self, interaction: discord.Interaction, user: discord.User, reason: Optional[str] = "Quarantine lifted by staff"):
        await interaction.response.defer(ephemeral=True)
        if not self._is_admin_or_owner(interaction.user, interaction.guild):
            await interaction.followup.send("❌ Only **Server Owners** and **Administrators** can lift quarantine.", ephemeral=True)
            return

        success, msg, embed = await self.unquarantine_member(interaction.guild, user.id, interaction.user, reason=reason)
        if success and embed:
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(msg, ephemeral=True)

    # ==========================================
    # PREFIX COMMANDS: !quarantine, !unquarantine, !quarantine_setup, !quarantine_view
    # ==========================================

    @commands.command(name="quarantine", aliases=["isolate"])
    async def cmd_quarantine(self, ctx: commands.Context, target: Optional[discord.Member] = None, *, reason: Optional[str] = "Quarantined by staff"):
        """Prefix command: !quarantine @member [reason]"""
        if not ctx.guild:
            return
        if not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Only **Server Owners** and **Administrators** can quarantine members.")
            return

        if not target:
            await ctx.send("ℹ️ **Usage:** `!quarantine @member [reason]`")
            return

        can_mod, err = self._can_moderate_target(ctx.author, target, ctx.guild)
        if not can_mod:
            await ctx.send(err)
            return

        success, msg, embed = await self.quarantine_member(ctx.guild, target, ctx.author, reason=reason)
        if success and embed:
            await ctx.send(embed=embed)
        else:
            await ctx.send(msg)

    @commands.command(name="quarantine_setup", aliases=["quarantinesetup"])
    async def cmd_quarantine_setup(self, ctx: commands.Context, role: discord.Role):
        """Prefix command: !quarantine_setup @role"""
        if not ctx.guild or not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Administrator or Server Owner permissions required.")
            return

        status_msg = await ctx.send("⚙️ **Setting up quarantine category, text channel, voice channel and server isolation...**")
        guild = ctx.guild
        me = guild.me
        if not me.guild_permissions.manage_channels or not me.guild_permissions.manage_roles:
            await status_msg.edit(content="❌ Bot lacks 'Manage Channels' or 'Manage Roles' permission.")
            return

        await db.set_quarantine_role(guild.id, role.id)
        settings = bot_config.guild_settings_cache.get(guild.id, {})
        settings["quarantine_role_id"] = role.id

        cat_overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False, connect=False),
            me: discord.PermissionOverwrite(view_channel=True, manage_channels=True, manage_permissions=True, send_messages=True, connect=True),
            role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True, connect=True, speak=True)
        }

        category = None
        for c in guild.categories:
            if "quarantine" in c.name.lower() or "isolation" in c.name.lower():
                category = c
                break

        if not category:
            category = await guild.create_category("🔒 Quarantine Zone", overwrites=cat_overwrites, reason=f"Quarantine setup by {ctx.author}")
        else:
            try:
                await category.set_permissions(guild.default_role, view_channel=False, connect=False)
                await category.set_permissions(role, view_channel=True, send_messages=True, read_message_history=True, connect=True, speak=True)
            except Exception:
                pass

        await db.set_quarantine_category(guild.id, category.id)
        settings["quarantine_category_id"] = category.id
        bot_config.guild_settings_cache[guild.id] = settings

        text_ch = None
        for ch in category.text_channels:
            if "quarantine" in ch.name.lower() or "chat" in ch.name.lower():
                text_ch = ch
                break
        if not text_ch:
            text_ch = await guild.create_text_channel(name="quarantine-chat", category=category, topic="Private holding area for quarantined members.")

        voice_ch = None
        for vc in category.voice_channels:
            if "quarantine" in vc.name.lower() or "voice" in vc.name.lower() or "vc" in vc.name.lower():
                voice_ch = vc
                break
        if not voice_ch:
            voice_ch = await guild.create_voice_channel(name="quarantine-voice", category=category)

        cats_h, chs_h, _ = await self.sync_quarantine_overwrites(guild, role, category)

        embed = discord.Embed(
            title="🛡️ Quarantine Setup Complete",
            color=discord.Color.green(),
            description=(
                f"**Quarantine Category & Channels Created & Isolated!**\n\n"
                f"🏷️ **Quarantine Role:** {role.mention} (`{role.id}`)\n"
                f"📁 **Quarantine Category:** `{category.name}`\n"
                f"💬 **Text Channel:** {text_ch.mention}\n"
                f"🔊 **Voice Channel:** {voice_ch.mention}\n\n"
                f"🔒 **Server Isolation Enforced:**\n"
                f"• `{cats_h}` other server categories hidden from {role.mention}\n"
                f"• `{chs_h}` uncategorized channels hidden from {role.mention}"
            ),
            timestamp=datetime.now(timezone.utc)
        )
        await status_msg.edit(content=None, embed=embed)

    @commands.command(name="quarantine_view", aliases=["quarantined", "quarantinelist"])
    async def cmd_quarantine_view(self, ctx: commands.Context):
        """Prefix command: !quarantine_view (lists active quarantined members)"""
        if not ctx.guild or not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Administrator or Server Owner permissions required.")
            return

        records = await db.get_all_quarantined(ctx.guild.id)
        if not records:
            await ctx.send("✅ There are currently **no members in quarantine** in this server.")
            return

        embed = discord.Embed(
            title=f"🔒 Quarantined Members in {ctx.guild.name} ({len(records)})",
            color=discord.Color.dark_red(),
            description="Members below have had all roles stripped and channel visibility revoked until manually released.\n",
            timestamp=datetime.now(timezone.utc)
        )

        for rec in records[:25]:
            uid = rec["user_id"]
            mem = ctx.guild.get_member(uid)
            display = f"{mem.mention} (`{uid}`)" if mem else f"User ID `{uid}` *(Left Server)*"
            roles_count = len(rec.get("saved_role_ids", []))
            mod = f"<@{rec['quarantined_by']}>"
            q_time = rec.get("quarantined_at", "Unknown")[:19].replace("T", " ")
            reason = rec.get("reason", "No reason provided")

            embed.add_field(
                name=f"👤 {display}",
                value=(
                    f"• **Reason:** {reason}\n"
                    f"• **Staff:** {mod}\n"
                    f"• **Backed-up Roles:** `{roles_count}` roles\n"
                    f"• **Quarantined At:** `{q_time} UTC`"
                ),
                inline=False
            )

        embed.set_footer(text="Use !unquarantine @user to release a member and restore their roles.")
        await ctx.send(embed=embed)

    @commands.command(name="unquarantine", aliases=["release"])
    async def cmd_unquarantine(self, ctx: commands.Context, user: Union[discord.Member, discord.User], *, reason: Optional[str] = "Quarantine lifted by staff"):
        """Prefix command: !unquarantine @user [reason]"""
        if not ctx.guild or not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Only **Server Owners** and **Administrators** can lift quarantine.")
            return

        success, msg, embed = await self.unquarantine_member(ctx.guild, user.id, ctx.author, reason=reason)
        if success and embed:
            await ctx.send(embed=embed)
        else:
            await ctx.send(msg)


async def setup(bot: commands.Bot):
    await bot.add_cog(QuarantineSystem(bot))

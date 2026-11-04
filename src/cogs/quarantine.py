"""Quarantine System Cog for Karuppu / Antigravity Security Bot.
Provides indefinite member isolation:
- Strips all member roles and backs them up in database.
- Assigns the Quarantine role.
- Enforces Category-level isolation: hides ALL server categories & channels except the designated Quarantine Category.
- Disconnects from and blocks voice channels.
- Persists across member rejoins and unauthorized role grants.
- Unquarantine by Admin/Owner restores all backed-up roles seamlessly.
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
                # Cache it in database
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
                    guild.default_role: discord.PermissionOverwrite(view_channel=False),
                    guild.me: discord.PermissionOverwrite(view_channel=True, manage_channels=True, manage_permissions=True)
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

                # Create default chat channel inside it
                await guild.create_text_channel(
                    name="quarantine-chat",
                    category=cat,
                    topic="Private holding channel for quarantined members. Only you and server staff can view this.",
                    reason="Auto-created quarantine chat"
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
                await quarantine_category.set_permissions(guild.default_role, overwrite=new_ev_ow, reason="Quarantine isolation: Hide from public")

                # Sync or ensure child channels in quarantine category allow quarantine role
                for ch in quarantine_category.channels:
                    try:
                        ch_ow = ch.overwrites.get(quarantine_role)
                        if ch_ow and ch_ow.view_channel is False:
                            ch_ow.view_channel = True
                            await ch.set_permissions(quarantine_role, overwrite=ch_ow, reason="Quarantine child channel view access")
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
            return False, "❌ No **Quarantine** role found or could be created. Please create a role named `Quarantine`.", None

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
    # SLASH COMMANDS: /quarantine, /unquarantine, /quarantined, /quarantine_setup, /quarantine_sync
    # ==========================================

    @app_commands.command(name="quarantine", description="[Admins/Owner Only] Strip all roles and isolate a member indefinitely.")
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
            # Add helpful tip if user is server owner
            if interaction.guild.owner_id == member.id:
                tip = "\n\n*(Note: Discord client always shows all channels to Server Owner. Use 'View Server as Role' to preview)*"
                embed.description += tip
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.followup.send(msg, ephemeral=True)

    @app_commands.command(name="unquarantine", description="[Admins/Owner Only] Lift quarantine and restore all original roles to a user.")
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

    @app_commands.command(name="quarantined", description="[Admins/Owner Only] View all members currently in quarantine.")
    async def slash_quarantined_list(self, interaction: discord.Interaction):
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

    @app_commands.command(
        name="quarantine_setup",
        description="[Admins Only] Configure quarantine role and isolated category (hides all other categories)."
    )
    @app_commands.describe(
        category="The ONLY category quarantined members can see (all other categories are hidden)",
        role="The role to use as Quarantine role (leave empty to auto-detect)",
        auto_sync="Immediately enforce view_channel=False across all other categories (default: True)"
    )
    async def slash_quarantine_setup(
        self,
        interaction: discord.Interaction,
        category: Optional[discord.CategoryChannel] = None,
        role: Optional[discord.Role] = None,
        auto_sync: Optional[bool] = True
    ):
        await interaction.response.defer(ephemeral=True)
        if not self._is_admin_or_owner(interaction.user, interaction.guild):
            await interaction.followup.send("❌ Administrator or Server Owner permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        settings = bot_config.guild_settings_cache.get(guild.id, {})
        changes = []

        if role:
            await db.set_quarantine_role(guild.id, role.id)
            settings["quarantine_role_id"] = role.id
            changes.append(f"• **Quarantine Role:** {role.mention} (`{role.id}`)")

        if category:
            await db.set_quarantine_category(guild.id, category.id)
            settings["quarantine_category_id"] = category.id
            changes.append(f"• **Quarantine Category:** `{category.name}` (`{category.id}`)")

        bot_config.guild_settings_cache[guild.id] = settings

        # Resolve current active role and category
        active_role = role or await self.get_or_create_quarantine_role(guild)
        active_category = category or await self.get_or_create_quarantine_category(guild, active_role)

        sync_summary = ""
        if auto_sync and active_role:
            cats_h, chs_h, errs = await self.sync_quarantine_overwrites(guild, active_role, active_category)
            cat_name = active_category.name if active_category else "None"
            sync_summary = (
                f"\n\n🛡️ **Channel Isolation Enforced:**\n"
                f"• **Allowed Category:** `{cat_name}`\n"
                f"• **Categories Hidden:** `{cats_h}` categories locked out for {active_role.mention}\n"
                f"• **Orphan Channels Hidden:** `{chs_h}` channels locked out\n"
                f"✅ Quarantined users can **only** see `{cat_name}`!"
            )
            if errs:
                sync_summary += f"\n⚠️ *Notices: {len(errs)} items (check role permissions)*"

        if not changes:
            curr_role_id = settings.get("quarantine_role_id")
            curr_cat_id = settings.get("quarantine_category_id")
            r_str = f"<@&{curr_role_id}>" if curr_role_id else "*Auto-detected*"
            c_str = f"`{guild.get_channel(curr_cat_id).name}`" if curr_cat_id and guild.get_channel(curr_cat_id) else "*Auto-detected*"
            await interaction.followup.send(
                f"⚙️ **Current Quarantine Configuration:**\n• **Role:** {r_str}\n• **Category:** {c_str}{sync_summary}\n\n*Provide `category` or `role` parameter to update.*",
                ephemeral=True
            )
            return

        embed = discord.Embed(
            title="⚙️ Quarantine Configuration Updated",
            color=discord.Color.green(),
            description="Successfully updated quarantine settings:\n\n" + "\n".join(changes) + sync_summary,
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text="Karuppu Quarantine Engine • Category Isolation Active")
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(
        name="quarantine_sync",
        description="[Admins Only] 1-Click sync to hide ALL server categories from quarantined members."
    )
    async def slash_quarantine_sync(self, interaction: discord.Interaction):
        """Immediately scans every category and channel in the server and locks them against the Quarantine role."""
        await interaction.response.defer(ephemeral=True)
        if not self._is_admin_or_owner(interaction.user, interaction.guild):
            await interaction.followup.send("❌ Administrator or Server Owner permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        quarantine_role = await self.get_or_create_quarantine_role(guild)
        if not quarantine_role:
            await interaction.followup.send("❌ No Quarantine role found or configured.", ephemeral=True)
            return

        quarantine_category = await self.get_or_create_quarantine_category(guild, quarantine_role)
        cats_h, chs_h, errs = await self.sync_quarantine_overwrites(guild, quarantine_role, quarantine_category)

        cat_desc = f"`{quarantine_category.name}`" if quarantine_category else "*None*"
        embed = discord.Embed(
            title="🔄 Quarantine Category Isolation Synced",
            color=discord.Color.green(),
            description=(
                f"**Server-Wide Quarantine Isolation Applied!**\n\n"
                f"🛡️ **Quarantine Role:** {quarantine_role.mention}\n"
                f"📁 **Allowed Category:** {cat_desc}\n"
                f"🚫 **Categories Hidden:** `{cats_h}` categories denied for {quarantine_role.mention}\n"
                f"🔒 **Orphan Channels Hidden:** `{chs_h}` channels denied\n\n"
                f"✅ **Result:** Quarantined members can **ONLY** view and speak inside {cat_desc}. All other server categories and channels are completely invisible to them!"
            ),
            timestamp=datetime.now(timezone.utc)
        )
        embed.set_footer(text="Karuppu Quarantine Isolation Engine")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ==========================================
    # PREFIX COMMANDS: !quarantine, !unquarantine, !quarantined, !quarantinesync
    # ==========================================

    @commands.command(name="quarantine", aliases=["isolate"])
    async def cmd_quarantine(self, ctx: commands.Context, target_or_subcmd: Optional[str] = None, *, extra_arg: Optional[str] = None):
        """Prefix command:
        - !quarantine @member [reason]
        - !quarantine sync
        - !quarantine setup <category_name_or_id>
        - !quarantine category <category_name_or_id>
        """
        if not ctx.guild:
            return
        if not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Only **Server Owners** and **Administrators** can run quarantine commands.")
            return

        # 1. Check subcommands: sync
        if target_or_subcmd and target_or_subcmd.lower() in ("sync", "resync"):
            quarantine_role = await self.get_or_create_quarantine_role(ctx.guild)
            if not quarantine_role:
                await ctx.send("❌ No Quarantine role found.")
                return
            quarantine_category = await self.get_or_create_quarantine_category(ctx.guild, quarantine_role)
            cats_h, chs_h, _ = await self.sync_quarantine_overwrites(ctx.guild, quarantine_role, quarantine_category)
            cat_desc = f"`{quarantine_category.name}`" if quarantine_category else "*None*"
            await ctx.send(f"✅ **Quarantine Isolation Synced!** Allowed Category: {cat_desc} | Hidden Categories: `{cats_h}` | Hidden Channels: `{chs_h}`.")
            return

        # 2. Check subcommands: setup / category
        if target_or_subcmd and target_or_subcmd.lower() in ("setup", "category", "setcategory"):
            if not extra_arg:
                await ctx.send("❌ Please specify the category name or ID: `!quarantine category <category_name_or_id>`")
                return

            # Find category
            found_cat = None
            clean_arg = extra_arg.strip().strip("<#>").strip()
            if clean_arg.isdigit():
                ch = ctx.guild.get_channel(int(clean_arg))
                if isinstance(ch, discord.CategoryChannel):
                    found_cat = ch

            if not found_cat:
                for cat in ctx.guild.categories:
                    if cat.name.lower() == extra_arg.lower() or extra_arg.lower() in cat.name.lower():
                        found_cat = cat
                        break

            if not found_cat:
                await ctx.send(f"❌ Could not find category matching `{extra_arg}` in this server.")
                return

            await db.set_quarantine_category(ctx.guild.id, found_cat.id)
            settings = bot_config.guild_settings_cache.get(ctx.guild.id, {})
            settings["quarantine_category_id"] = found_cat.id
            bot_config.guild_settings_cache[ctx.guild.id] = settings

            quarantine_role = await self.get_or_create_quarantine_role(ctx.guild)
            cats_h, chs_h, _ = await self.sync_quarantine_overwrites(ctx.guild, quarantine_role, found_cat)

            await ctx.send(
                f"✅ **Quarantine Category Updated to `{found_cat.name}`!**\n"
                f"• `{cats_h}` other categories hidden.\n"
                f"• `{chs_h}` orphaned channels hidden.\n"
                f"Quarantined users will now **only** see `{found_cat.name}`."
            )
            return

        # 3. Standard member quarantine: !quarantine @member [reason]
        if not target_or_subcmd:
            await ctx.send("ℹ️ **Usage:**\n• `!quarantine @member [reason]`\n• `!quarantine sync`\n• `!quarantine category <category_name>`\n• `!unquarantine @member`\n• `!quarantined`")
            return

        # Resolve member
        target_member = None
        if ctx.message.mentions:
            target_member = ctx.message.mentions[0]
        else:
            clean_id = target_or_subcmd.strip("<@!>").strip()
            if clean_id.isdigit():
                target_member = ctx.guild.get_member(int(clean_id))

        if not target_member:
            await ctx.send(f"❌ Could not find member `{target_or_subcmd}`. Please mention the member: `!quarantine @user [reason]`")
            return

        can_mod, err = self._can_moderate_target(ctx.author, target_member, ctx.guild)
        if not can_mod:
            await ctx.send(err)
            return

        reason = extra_arg or "Quarantined by staff"
        success, msg, embed = await self.quarantine_member(ctx.guild, target_member, ctx.author, reason=reason)
        if success and embed:
            await ctx.send(embed=embed)
        else:
            await ctx.send(msg)

    @commands.command(name="quarantinesync", aliases=["qsync"])
    async def cmd_quarantine_sync(self, ctx: commands.Context):
        """Prefix command: !quarantinesync (hides all server categories from quarantine role)"""
        if not ctx.guild or not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Administrator or Server Owner permissions required.")
            return

        quarantine_role = await self.get_or_create_quarantine_role(ctx.guild)
        if not quarantine_role:
            await ctx.send("❌ No Quarantine role found.")
            return

        quarantine_category = await self.get_or_create_quarantine_category(ctx.guild, quarantine_role)
        cats_h, chs_h, _ = await self.sync_quarantine_overwrites(ctx.guild, quarantine_role, quarantine_category)
        cat_desc = f"`{quarantine_category.name}`" if quarantine_category else "*None*"

        await ctx.send(
            f"✅ **Quarantine Isolation Synced!**\n"
            f"• **Allowed Category:** {cat_desc}\n"
            f"• **Hidden Categories:** `{cats_h}`\n"
            f"• **Hidden Orphan Channels:** `{chs_h}`\n\n"
            f"Quarantined members are now completely restricted to {cat_desc}."
        )

    @commands.command(name="unquarantine", aliases=["release"])
    async def cmd_unquarantine(self, ctx: commands.Context, user_arg: Optional[str] = None, *, reason: Optional[str] = "Quarantine lifted by staff"):
        """Prefix command: !unquarantine @user [reason]"""
        if not ctx.guild:
            return
        if not self._is_admin_or_owner(ctx.author, ctx.guild):
            await ctx.send("❌ Only **Server Owners** and **Administrators** can lift quarantine.")
            return

        if not user_arg:
            await ctx.send("ℹ️ **Usage:** `!unquarantine @user [reason]`")
            return

        target_uid = None
        if ctx.message.mentions:
            target_uid = ctx.message.mentions[0].id
        else:
            clean_id = user_arg.strip("<@!>").strip()
            if clean_id.isdigit():
                target_uid = int(clean_id)

        if not target_uid:
            await ctx.send(f"❌ Invalid user: `{user_arg}`. Mention the user: `!unquarantine @user`")
            return

        success, msg, embed = await self.unquarantine_member(ctx.guild, target_uid, ctx.author, reason=reason)
        if success and embed:
            await ctx.send(embed=embed)
        else:
            await ctx.send(msg)

    @commands.command(name="quarantined", aliases=["quarantinelist"])
    async def cmd_quarantined_list(self, ctx: commands.Context):
        """Prefix command: !quarantined (lists active quarantined members)"""
        if not ctx.guild:
            return
        if not self._is_admin_or_owner(ctx.author, ctx.guild):
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


async def setup(bot: commands.Bot):
    await bot.add_cog(QuarantineSystem(bot))

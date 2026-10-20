"""Admin & Owner Management Cog.
Handles owner-only bypass configuration, lockdown triggers, dry-run toggles, and security health audits.
"""
import logging
from typing import Optional
import discord
from discord import app_commands
from discord.ext import commands
from src.config import bot_config
from src.database import db

logger = logging.getLogger("security_bot.admin")

class RaidPurgeConfirmView(discord.ui.View):
    def __init__(self, candidates: list, action_type: str, moderator: discord.Member):
        super().__init__(timeout=60)
        self.candidates = candidates
        self.action_type = action_type
        self.moderator = moderator

    @discord.ui.button(label="Confirm Purge", style=discord.ButtonStyle.danger, emoji="⚠️")
    async def confirm_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the moderator who initiated the purge can confirm it.", ephemeral=True)
            return

        await interaction.response.defer()
        for child in self.children:
            child.disabled = True

        executed_count = 0
        guild = interaction.guild
        for mem in self.candidates:
            try:
                if self.action_type == "ban":
                    await guild.ban(mem, reason=f"Mass raid purge confirmed by {interaction.user}", delete_message_days=1)
                else:
                    await guild.kick(mem, reason=f"Mass raid purge confirmed by {interaction.user}")
                executed_count += 1
            except Exception as e:
                logger.warning("Failed to purge raid member %s: %s", mem, e)

        embed = discord.Embed(
            title=f"🧹 Raid Purge Complete: {executed_count} Accounts {self.action_type.title()}ed",
            color=discord.Color.green(),
            description=f"Successfully purged **{executed_count}** accounts that joined during the raid wave.\n**Moderator:** {interaction.user.mention}"
        )
        await interaction.message.edit(embed=embed, view=self)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="❌")
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the initiator can cancel.", ephemeral=True)
            return

        for child in self.children:
            child.disabled = True
        await interaction.message.edit(content="❌ Raid purge was cancelled. No members were affected.", embed=None, view=self)
        await interaction.response.send_message("Purge cancelled.", ephemeral=True)


class SecurityAdmin(commands.GroupCog, name="security"):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        super().__init__()

    def _check_owner(self, interaction: discord.Interaction) -> bool:
        """Enforces that only the server owner can execute bypass controls."""
        return bot_config.is_guild_owner(interaction.guild, interaction.user.id)

    def _check_mod(self, interaction: discord.Interaction) -> bool:
        """Enforces moderator or admin permissions."""
        if self._check_owner(interaction):
            return True
        user = interaction.user
        return (
            isinstance(user, discord.Member) and
            (user.guild_permissions.administrator or user.guild_permissions.moderate_members)
        )

    # ==========================================
    # OWNER-ONLY BYPASS COMMANDS
    # ==========================================
    bypass_group = app_commands.Group(name="bypass", description="Owner-only security bypass management")

    @bypass_group.command(name="add_role", description="[Owner Only] Grant a role total bypass from security gates.")
    @app_commands.describe(role="The role to grant bypass")
    async def bypass_add_role(self, interaction: discord.Interaction, role: discord.Role):
        if not self._check_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner can configure bypasses.", ephemeral=True)
            return

        bot_config.dynamic_bypass_roles.add(role.id)
        await db.add_dynamic_bypass("role", role.id, role.name, interaction.user.id)
        await interaction.response.send_message(f"✅ Role **{role.name}** (`{role.id}`) added to security bypass list by Server Owner.", ephemeral=True)

    @bypass_group.command(name="remove_role", description="[Owner Only] Revoke a role's bypass.")
    @app_commands.describe(role="The role to remove from bypass")
    async def bypass_remove_role(self, interaction: discord.Interaction, role: discord.Role):
        if not self._check_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner can configure bypasses.", ephemeral=True)
            return

        bot_config.dynamic_bypass_roles.discard(role.id)
        await db.remove_dynamic_bypass(role.id)
        await interaction.response.send_message(f"🗑️ Role **{role.name}** (`{role.id}`) removed from bypass list.", ephemeral=True)

    @bypass_group.command(name="add_user", description="[Owner Only] Grant a specific user total bypass.")
    @app_commands.describe(user="The user to grant bypass")
    async def bypass_add_user(self, interaction: discord.Interaction, user: discord.Member):
        if not self._check_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner can configure bypasses.", ephemeral=True)
            return

        bot_config.dynamic_bypass_users.add(user.id)
        await db.add_dynamic_bypass("user", user.id, str(user), interaction.user.id)
        await interaction.response.send_message(f"✅ Member **{user}** (`{user.id}`) added to security bypass list by Server Owner.", ephemeral=True)

    @bypass_group.command(name="remove_user", description="[Owner Only] Revoke a user's bypass.")
    @app_commands.describe(user="The user to remove from bypass")
    async def bypass_remove_user(self, interaction: discord.Interaction, user: discord.Member):
        if not self._check_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner can configure bypasses.", ephemeral=True)
            return

        bot_config.dynamic_bypass_users.discard(user.id)
        await db.remove_dynamic_bypass(user.id)
        await interaction.response.send_message(f"🗑️ Member **{user}** (`{user.id}`) removed from bypass list.", ephemeral=True)

    @bypass_group.command(name="add_channel", description="[Owner Only] Exempt a channel from security monitoring.")
    @app_commands.describe(channel="The channel to exempt")
    async def bypass_add_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not self._check_owner(interaction):
            await interaction.response.send_message("❌ **Access Denied**: Only the Server Owner can configure bypasses.", ephemeral=True)
            return

        bot_config.dynamic_bypass_channels.add(channel.id)
        await db.add_dynamic_bypass("channel", channel.id, f"#{channel.name}", interaction.user.id)
        await interaction.response.send_message(f"✅ Channel {channel.mention} (`{channel.id}`) added to security exemption list.", ephemeral=True)

    @bypass_group.command(name="list", description="List all owner-authorized bypass roles, users, and channels.")
    async def bypass_list(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required to view bypasses.", ephemeral=True)
            return

        bypasses = await db.get_all_bypasses()
        roles_txt = []
        users_txt = []
        channels_txt = []

        # Config file pre-seeded bypasses
        cfg_roles = bot_config.raw_data.get("owner_bypasses", {}).get("roles", [])
        cfg_users = bot_config.raw_data.get("owner_bypasses", {}).get("users", [])
        cfg_channels = bot_config.raw_data.get("owner_bypasses", {}).get("channels", [])

        for r in cfg_roles:
            roles_txt.append(f"`{r}` *(config.yaml)*")
        for u in cfg_users:
            users_txt.append(f"<@{u}> *(config.yaml)*")
        for c in cfg_channels:
            channels_txt.append(f"<#{c}> *(config.yaml)*")

        for b in bypasses:
            b_type = b["bypass_type"]
            t_id = b["target_id"]
            name = b["target_name"]
            if b_type == "role":
                roles_txt.append(f"<@&{t_id}> (`{name}`)")
            elif b_type == "user":
                users_txt.append(f"<@{t_id}> (`{name}`)")
            elif b_type == "channel":
                channels_txt.append(f"<#{t_id}> (`{name}`)")

        embed = discord.Embed(
            title="🛡️ Owner-Configured Security Bypasses",
            color=discord.Color.blue(),
            description="Members and locations granted complete exemption from security filters:"
        )
        embed.add_field(name="Exempt Roles", value="\n".join(roles_txt) if roles_txt else "*None configured*", inline=False)
        embed.add_field(name="Exempt Users", value="\n".join(users_txt) if users_txt else "*None configured*", inline=False)
        embed.add_field(name="Exempt Channels", value="\n".join(channels_txt) if channels_txt else "*None configured*", inline=False)
        embed.set_footer(text="Managed exclusively by the Server Owner")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ==========================================
    # SERVER ROLE SELECTION & PUBLIC SETUP
    # ==========================================
    @app_commands.command(name="set_role", description="[Admins Only] Select which role unlocks a specific security permission.")
    @app_commands.describe(
        gate="Which security gate to configure",
        role="The role required to unlock this privilege"
    )
    @app_commands.choices(gate=[
        app_commands.Choice(name="External Links & URLs (Link Gate)", value="links"),
        app_commands.Choice(name="GIFs & Media Attachments (Media Gate)", value="media"),
        app_commands.Choice(name="Microphone in Voice Channels (VC Mic Gate)", value="mic"),
        app_commands.Choice(name="ZIP / RAR Archives (Archive Gate)", value="archives"),
        app_commands.Choice(name="Discord Server Invites (Invite Gate)", value="invites"),
    ])
    async def cmd_set_role(self, interaction: discord.Interaction, gate: app_commands.Choice[str], role: discord.Role):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        await db.update_guild_role_gate(guild_id, gate.value, role.id, role.name)

        # Update cache
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id][f"{gate.value}_role_id"] = role.id
        bot_config.guild_settings_cache[guild_id][f"{gate.value}_role_name"] = role.name

        embed = discord.Embed(
            title="✅ Level Gate Role Updated",
            color=discord.Color.green(),
            description=(
                f"**Permission Gate:** `{gate.name}`\n"
                f"**Required Role:** {role.mention} (`{role.name}`)\n\n"
                f"Members with **{role.name}** (or higher level ranks) can now use this feature!"
            )
        )
        embed.set_footer(text=f"Updated by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="set_alert_channel", description="[Admins Only] Select the channel where security alerts and mod cards are sent.")
    @app_commands.describe(channel="The channel for mod logs and raid alerts")
    async def cmd_set_alert_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        await db.set_alert_channel(guild_id, channel.id)

        # Update cache
        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id]["alert_channel_id"] = channel.id

        embed = discord.Embed(
            title="📢 Alert Channel Updated",
            color=discord.Color.blue(),
            description=f"Security alerts, raid cards, and scam notifications will now be posted to {channel.mention}."
        )
        embed.set_footer(text=f"Configured by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="set_log_channel", description="[Admins Only] Assign a dedicated channel for a specific log type.")
    @app_commands.describe(
        category="Which log category to configure",
        channel="The channel where these logs should be posted"
    )
    @app_commands.choices(category=[
        app_commands.Choice(name="💬 Chat Logs (Message Edits & Deletions)", value="chat"),
        app_commands.Choice(name="🔊 Voice Logs (VC Joins, Leaves & Switches)", value="voice"),
        app_commands.Choice(name="👥 Member Logs (Joins, Leaves & Account Age)", value="member"),
        app_commands.Choice(name="🔨 Mod Logs (Bans, Kicks, Timeouts & Reasons)", value="mod"),
        app_commands.Choice(name="📁 Server Logs (Channel & Role Changes)", value="server"),
    ])
    async def cmd_set_log_channel(self, interaction: discord.Interaction, category: app_commands.Choice[str], channel: discord.TextChannel):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        await db.set_log_channel(guild_id, category.value, channel.id)

        if guild_id not in bot_config.guild_settings_cache:
            bot_config.guild_settings_cache[guild_id] = {}
        bot_config.guild_settings_cache[guild_id][f"{category.value}_log_channel_id"] = channel.id

        embed = discord.Embed(
            title="📑 Dedicated Log Channel Configured",
            color=discord.Color.green(),
            description=(
                f"**Category:** `{category.name}`\n"
                f"**Log Destination:** {channel.mention}\n\n"
                f"All future events for this category will be logged here."
            )
        )
        embed.set_footer(text=f"Configured by {interaction.user}")
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="setup_all_logs", description="[Admins Only] Automatically creates a private '📑 LOGS' category with all 5 log channels.")
    async def cmd_setup_all_logs(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        me = guild.me
        if not me.guild_permissions.manage_channels:
            await interaction.response.send_message("❌ Bot lacks the 'Manage Channels' permission to create log channels.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        # Overwrites: visible only to Admins/Mods and the bot
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            me: discord.PermissionOverwrite(read_messages=True, send_messages=True, embed_links=True)
        }

        try:
            category = await guild.create_category("📑 SECURITY LOGS", overwrites=overwrites, reason="Automated security logs setup")

            log_defs = [
                ("chat-logs", "chat", "Message edits & deletions"),
                ("voice-logs", "voice", "VC joins, leaves & switches"),
                ("join-leave-logs", "member", "Member joins, leaves & account age warnings"),
                ("mod-logs", "mod", "Bans, kicks, timeouts, who did what to whom + reasons"),
                ("server-logs", "server", "Channel and role creations/deletions")
            ]

            created_channels = []
            for name, cat_key, desc in log_defs:
                ch = await guild.create_text_channel(name, category=category, topic=desc, reason="Automated security logs setup")
                await db.set_log_channel(guild.id, cat_key, ch.id)
                if guild.id not in bot_config.guild_settings_cache:
                    bot_config.guild_settings_cache[guild.id] = {}
                bot_config.guild_settings_cache[guild.id][f"{cat_key}_log_channel_id"] = ch.id
                created_channels.append(ch)

            channels_str = "\n".join([f"• {c.mention} — `{c.topic}`" for c in created_channels])
            embed = discord.Embed(
                title="✅ Dedicated Log Channels Created & Bound!",
                color=discord.Color.green(),
                description=(
                    f"Created private category **{category.name}** with 5 dedicated log channels:\n\n"
                    f"{channels_str}\n\n"
                    f"🔒 *These channels are locked and hidden from regular members. Only staff and the bot can view them.*"
                )
            )
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            logger.error("Failed creating log channels: %s", e)
            await interaction.followup.send(f"❌ Error creating log channels: {e}", ephemeral=True)

    @app_commands.command(name="setup", description="View current security configuration and level role gates for this server.")
    async def cmd_setup(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        guild = interaction.guild
        g_cfg = bot_config.guild_settings_cache.get(guild.id, {})
        alert_ch_id = g_cfg.get("alert_channel_id", bot_config.alert_channel_id)
        alert_ch_str = f"<#{alert_ch_id}>" if alert_ch_id else "*Not configured (run `/security set_alert_channel`)*"

        def _format_gate(gate_name, default_name):
            r_id = g_cfg.get(f"{gate_name}_role_id")
            r_name = g_cfg.get(f"{gate_name}_role_name")
            if r_id:
                return f"<@&{r_id}> (`{r_name}`)"
            return f"`{default_name}` *(Default)*"

        def _format_ch(category):
            c_id = g_cfg.get(f"{category}_log_channel_id")
            return f"<#{c_id}>" if c_id else "*Not set*"

        embed = discord.Embed(
            title=f"🛡️ Security Configuration: {guild.name}",
            color=discord.Color.blue(),
            description="Here are the active security gates and role requirements for this server:"
        )
        embed.add_field(name="📢 Moderator Alert Channel", value=alert_ch_str, inline=False)
        embed.add_field(
            name="🔒 Configured Level Gates",
            value=(
                f"• **External Links & URLs:** {_format_gate('links', 'Guild Recruit')}\n"
                f"• **GIFs & Media:** {_format_gate('media', 'Guild Recruit')}\n"
                f"• **Voice Channel Mic:** {_format_gate('mic', 'Guild Recruit')}\n"
                f"• **ZIP / RAR Archives:** {_format_gate('archives', 'Bronze Rank')}\n"
                f"• **Server Invites:** {_format_gate('invites', 'Bronze Rank')}"
            ),
            inline=False
        )
        embed.add_field(
            name="📑 Dedicated Log Channels",
            value=(
                f"• **Chat Logs (Edits/Deletes):** {_format_ch('chat')}\n"
                f"• **Voice Logs (VC Join/Leave/Switch):** {_format_ch('voice')}\n"
                f"• **Member Logs (Join/Leave + Age):** {_format_ch('member')}\n"
                f"• **Mod Logs (Bans/Kicks/Timeouts):** {_format_ch('mod')}\n"
                f"• **Server Logs (Channel/Role Changes):** {_format_ch('server')}"
            ),
            inline=False
        )
        embed.add_field(
            name="💡 Quick Tips",
            value=(
                "• Set individual log channels: `/security set_log_channel <category> <channel>`\n"
                "• Auto-create all 5 log channels in 1 click: `/security setup_all_logs`\n"
                "• Type `/help` for the complete guide!"
            ),
            inline=False
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ==========================================
    # MODERATION & OPERATIONAL CONTROLS
    # ==========================================
    @app_commands.command(name="lockdown", description="Activate a temporary emergency lockdown on public channels.")
    @app_commands.describe(duration_minutes="Duration in minutes (default 15, max 120)", reason="Reason for lockdown")
    async def cmd_lockdown(self, interaction: discord.Interaction, duration_minutes: Optional[int] = 15, reason: Optional[str] = "Emergency Moderation Lockdown"):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required to initiate lockdown.", ephemeral=True)
            return

        duration = min(max(duration_minutes or 15, 1), 120)
        lockdown_cog = self.bot.get_cog("ServerLockdown")
        if not lockdown_cog:
            await interaction.response.send_message("❌ Lockdown module is not loaded.", ephemeral=True)
            return

        await interaction.response.defer()
        success, msg = await lockdown_cog.apply_lockdown(
            guild=interaction.guild,
            duration_minutes=duration,
            reason=reason or "Emergency Lockdown",
            moderator=interaction.user
        )

        if success:
            embed = discord.Embed(
                title="🔒 Emergency Server Lockdown Initiated",
                description=(
                    f"**Duration:** `{duration}` minutes (auto-expiring)\n"
                    f"**Reason:** {reason}\n"
                    f"**Moderator:** {interaction.user.mention}\n\n"
                    f"{msg}\n\n"
                    f"Use `/security unlock` to reverse the lockdown at any time."
                ),
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(f"❌ {msg}", ephemeral=True)

    @app_commands.command(name="unlock", description="Lift an active server lockdown immediately.")
    async def cmd_unlock(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        lockdown_cog = self.bot.get_cog("ServerLockdown")
        if not lockdown_cog:
            await interaction.response.send_message("❌ Lockdown module is not loaded.", ephemeral=True)
            return

        await interaction.response.defer()
        success, msg = await lockdown_cog.lift_lockdown(interaction.guild, moderator=interaction.user)
        if success:
            embed = discord.Embed(
                title="🔓 Server Lockdown Reversed",
                description=f"{msg}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.green()
            )
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(f"ℹ️ {msg}", ephemeral=True)

    @app_commands.command(name="purge_raid", description="[Admins Only] One-click purge of all accounts that joined during a raid wave.")
    @app_commands.describe(
        within_minutes="How many minutes ago the raid started (default 15, max 60)",
        require_no_roles="Only purge members with 0 roles (default True to protect regular members)",
        action="Action to execute: 'kick' or 'ban' (default kick)"
    )
    async def cmd_purge_raid(
        self,
        interaction: discord.Interaction,
        within_minutes: Optional[int] = 15,
        require_no_roles: Optional[bool] = True,
        action: Optional[str] = "kick"
    ):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        minutes = min(max(within_minutes or 15, 1), 60)
        action_type = "ban" if action and action.lower() == "ban" else "kick"
        guild = interaction.guild

        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        candidates = []
        for mem in guild.members:
            if mem.bot or mem.id == guild.owner_id:
                continue
            if bot_config.is_bypassed(guild, mem):
                continue
            # Check join time
            if mem.joined_at and mem.joined_at >= cutoff:
                # If require_no_roles is True, member should only have @everyone role
                if require_no_roles and len(mem.roles) > 1:
                    continue
                candidates.append(mem)

        if not candidates:
            await interaction.response.send_message(
                f"ℹ️ No candidate raid accounts found who joined in the last `{minutes}` minutes.",
                ephemeral=True
            )
            return

        sample_preview = ", ".join([f"<@{m.id}>" for m in candidates[:8]])
        if len(candidates) > 8:
            sample_preview += f" *(and {len(candidates) - 8} more)*"

        embed = discord.Embed(
            title="⚠️ Confirm Raid Purge Execution",
            color=discord.Color.red(),
            description=(
                f"A raid purge scan identified **{len(candidates)} accounts** matching criteria:\n\n"
                f"• **Joined within:** Last `{minutes}` minutes\n"
                f"• **Role Filter:** `{'Zero assigned roles' if require_no_roles else 'Any role'}`\n"
                f"• **Selected Action:** `{action_type.upper()}`\n\n"
                f"**Sample Accounts:** {sample_preview}\n\n"
                f"**Confirm below to execute this action.**"
            )
        )
        view = RaidPurgeConfirmView(candidates=candidates, action_type=action_type, moderator=interaction.user)
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    @app_commands.command(name="toggle_dry_run", description="Toggle between Dry-Run (Alert Only) and Active Enforcement.")
    async def cmd_toggle_dry_run(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        new_val = not bot_config.dry_run
        bot_config.dry_run = new_val
        bot_config.save_yaml()

        status_text = "DRY-RUN MODE (Alerts Only, No Automated Punishments)" if new_val else "ACTIVE ENFORCEMENT (Auto-deleting violations & applying timeouts)"
        color = discord.Color.gold() if new_val else discord.Color.green()

        embed = discord.Embed(
            title="⚙️ Operational Mode Updated",
            description=f"Security bot is now running in:\n**{status_text}**\n\nUpdated by {interaction.user.mention}.",
            color=color
        )
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="status", description="Displays security status, active rules, level gates, and health.")
    async def cmd_status(self, interaction: discord.Interaction):
        if not self._check_mod(interaction):
            await interaction.response.send_message("❌ Moderator permissions required.", ephemeral=True)
            return

        trust_cfg = bot_config.progressive_trust
        link_role = trust_cfg.get("link_gate", {}).get("required_role", "Disabled")
        gif_role = trust_cfg.get("media_and_gif_gate", {}).get("required_role", "Disabled")

        embed = discord.Embed(
            title="🛡️ Discord Security Suite Status",
            color=discord.Color.blue()
        )
        embed.add_field(
            name="Operational Mode",
            value=f"`{'DRY RUN (Simulated)' if bot_config.dry_run else 'ACTIVE ENFORCEMENT'}`",
            inline=True
        )
        embed.add_field(name="Bot Latency", value=f"`{round(self.bot.latency * 1000)}ms`", inline=True)
        embed.add_field(name="Guilds Monitored", value=f"`{len(self.bot.guilds)}`", inline=True)

        # Progressive trust summary
        voice_cfg = bot_config.raw_data.get("voice_protection", {})
        mic_role = voice_cfg.get("mic_gate", {}).get("required_role", "Disabled")

        embed.add_field(
            name="Progressive Trust (Level Gates)",
            value=(
                f"• **Links:** Requires `{link_role}`\n"
                f"• **GIFs/Media:** Requires `{gif_role}`\n"
                f"• **VC Microphone:** Requires `{mic_role}`\n"
                f"• **Bypass Control:** Exclusively Server Owner"
            ),
            inline=False
        )

        # Threats enabled
        embed.add_field(
            name="Threat Modules",
            value=(
                f"• **Anti-Raid Detector:** `{'Enabled' if bot_config.raid_detector.get('enabled') else 'Disabled'}`\n"
                f"• **Anti-Spam / Burst:** `{'Enabled' if bot_config.spam_detector.get('enabled') else 'Disabled'}`\n"
                f"• **Phishing Filter:** `{'Enabled' if bot_config.phishing_detector.get('enabled') else 'Disabled'}`\n"
                f"• **Voice Channel Defense:** `{'Enabled' if voice_cfg.get('enabled') else 'Disabled'}`"
            ),
            inline=False
        )
        embed.set_footer(text=f"Requested by {interaction.user}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

async def setup(bot: commands.Bot):
    await bot.add_cog(SecurityAdmin(bot))

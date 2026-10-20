"""Interactive Discord UI views and modals for security alerts and human-gated actions."""
import logging
from datetime import timedelta
from typing import Optional
import discord
from discord import ui
from src.database import db

logger = logging.getLogger("security_bot.moderation_view")

class BanConfirmationModal(ui.Modal, title="Confirm High-Impact Ban"):
    def __init__(self, target_member: discord.Member, incident_id: int):
        super().__init__()
        self.target_member = target_member
        self.incident_id = incident_id

        self.reason_input = ui.TextInput(
            label="Ban Reason",
            style=discord.TextStyle.short,
            placeholder="e.g. Confirmed malicious raid bot / phishing distributor",
            required=True,
            max_length=150
        )
        self.confirm_input = ui.TextInput(
            label='Type "CONFIRM" to execute ban',
            style=discord.TextStyle.short,
            placeholder="CONFIRM",
            required=True,
            min_length=7,
            max_length=7
        )
        self.add_item(self.reason_input)
        self.add_item(self.confirm_input)

    async def on_submit(self, interaction: discord.Interaction):
        if self.confirm_input.value.strip().upper() != "CONFIRM":
            await interaction.response.send_message("❌ Ban canceled: Confirmation word did not match.", ephemeral=True)
            return

        # Check moderator permissions
        if not interaction.user.guild_permissions.ban_members:
            await interaction.response.send_message("❌ You do not have permission to ban members.", ephemeral=True)
            return

        try:
            reason = f"[Security Bot Mod Action by {interaction.user}] {self.reason_input.value}"
            await self.target_member.guild.ban(self.target_member, reason=reason, delete_message_days=1)
            await db.update_incident_status(self.incident_id, "BANNED_BY_MOD", interaction.user.id)
            await interaction.response.send_message(
                f"🔨 **{self.target_member}** (ID: `{self.target_member.id}`) was banned by {interaction.user.mention}.\nReason: {self.reason_input.value}",
                ephemeral=False
            )
        except discord.Forbidden:
            await interaction.response.send_message("❌ Failed to ban: Bot lacks permission or member has higher role hierarchy.", ephemeral=True)
        except Exception as e:
            logger.error("Error executing confirmed ban: %s", e)
            await interaction.response.send_message(f"❌ Error executing ban: {e}", ephemeral=True)


class SecurityAlertView(ui.View):
    def __init__(
        self,
        incident_id: int,
        guild_id: int,
        target_user_id: int,
        target_username: str,
        message_id: Optional[int] = None,
        channel_id: Optional[int] = None
    ):
        super().__init__(timeout=86400) # View remains interactive for 24 hours
        self.incident_id = incident_id
        self.guild_id = guild_id
        self.target_user_id = target_user_id
        self.target_username = target_username
        self.message_id = message_id
        self.channel_id = channel_id

    def _is_mod(self, user: discord.Member) -> bool:
        """Verifies if interaction user has moderator privileges."""
        return (
            user.guild_permissions.moderate_members or
            user.guild_permissions.manage_messages or
            user.guild_permissions.administrator or
            user.guild.owner_id == user.id
        )

    @ui.button(label="Dismiss (False Positive)", style=discord.ButtonStyle.secondary, emoji="🛡️")
    async def dismiss_button(self, interaction: discord.Interaction, button: ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Only moderators can review security alerts.", ephemeral=True)
            return

        await db.update_incident_status(self.incident_id, "DISMISSED", interaction.user.id)
        
        # Disable all buttons
        for child in self.children:
            child.disabled = True

        embed = interaction.message.embeds[0] if interaction.message.embeds else None
        if embed:
            embed.color = discord.Color.light_grey()
            embed.title = f"[DISMISSED] {embed.title}"
            embed.set_footer(text=f"Dismissed by {interaction.user} (ID: {interaction.user.id})")
            await interaction.message.edit(embed=embed, view=self)

        await interaction.response.send_message(f"✅ Alert #{self.incident_id} marked as False Positive by {interaction.user.mention}.", ephemeral=True)

    @ui.button(label="Timeout (10m)", style=discord.ButtonStyle.primary, emoji="⏱️")
    async def timeout_button(self, interaction: discord.Interaction, button: ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Only moderators can timeout members.", ephemeral=True)
            return

        guild = interaction.guild
        member = guild.get_member(self.target_user_id) if guild else None

        if not member:
            await interaction.response.send_message("❌ Member is no longer in this server.", ephemeral=True)
            return

        try:
            await member.timeout(timedelta(minutes=10), reason=f"Security alert #{self.incident_id} applied by {interaction.user}")
            await db.update_incident_status(self.incident_id, "TIMEOUT_APPLIED", interaction.user.id)
            button.disabled = True
            button.label = "Timed Out (10m)"
            await interaction.message.edit(view=self)
            await interaction.response.send_message(f"⏱️ Timed out {member.mention} for 10 minutes.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("❌ Failed: Bot lacks permission or member has higher role hierarchy.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Error applying timeout: {e}", ephemeral=True)

    @ui.button(label="Delete Message", style=discord.ButtonStyle.danger, emoji="🗑️")
    async def delete_button(self, interaction: discord.Interaction, button: ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Only moderators can delete messages.", ephemeral=True)
            return

        if not self.channel_id or not self.message_id:
            await interaction.response.send_message("❌ No target message associated with this incident.", ephemeral=True)
            return

        channel = interaction.guild.get_channel(self.channel_id)
        if not channel:
            await interaction.response.send_message("❌ Channel not found.", ephemeral=True)
            return

        try:
            msg = await channel.fetch_message(self.message_id)
            await msg.delete()
            button.disabled = True
            button.label = "Message Deleted"
            await interaction.message.edit(view=self)
            await interaction.response.send_message("🗑️ Offending message deleted successfully.", ephemeral=True)
        except discord.NotFound:
            await interaction.response.send_message("ℹ️ Message was already deleted.", ephemeral=True)
            button.disabled = True
            await interaction.message.edit(view=self)
        except discord.Forbidden:
            await interaction.response.send_message("❌ Bot lacks 'Manage Messages' permission in that channel.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Could not delete message: {e}", ephemeral=True)

    @ui.button(label="Ban Account...", style=discord.ButtonStyle.danger, emoji="🔨")
    async def ban_button(self, interaction: discord.Interaction, button: ui.Button):
        if not self._is_mod(interaction.user):
            await interaction.response.send_message("❌ Only moderators can initiate bans.", ephemeral=True)
            return

        guild = interaction.guild
        member = guild.get_member(self.target_user_id) if guild else None
        if not member:
            await interaction.response.send_message("❌ Target member is no longer in this server.", ephemeral=True)
            return

        modal = BanConfirmationModal(target_member=member, incident_id=self.incident_id)
        await interaction.response.send_modal(modal)

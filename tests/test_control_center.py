"""Unit tests for the Unified Control Center, interactive embed views, and modals."""
import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import discord
from discord.ext import commands
from src.cogs.control_center import (
    ControlCenter,
    resolve_member_input,
    QuarantineModal,
    UnquarantineModal,
    RestoreRolesModal,
    VoiceKickModal,
    VoiceTimeoutModal,
    VoiceBanModal,
    LogSetupModal,
    SecurityControlView,
    QuarantineControlView,
    VoiceControlView,
    LogsControlView,
    MasterPanelView,
    MasterDropdown
)
from src.config import bot_config


class TestControlCenterComponents(unittest.TestCase):
    def setUp(self):
        self.bot = MagicMock(spec=commands.Bot)
        self.bot.latency = 0.045
        self.guild = MagicMock(spec=discord.Guild)
        self.guild.id = 123456789012345678
        self.guild.name = "DefenseHQ"
        self.guild.owner_id = 999999999999999999
        self.guild.fetch_member = AsyncMock(return_value=None)

        self.mod = MagicMock(spec=discord.Member)
        self.mod.id = 888888888888888888
        self.mod.guild_permissions = discord.Permissions(administrator=True)

    def test_security_control_view_structure(self):
        view = SecurityControlView(self.bot, self.guild, self.mod)
        view.stop()
        labels = [item.label for item in view.children if hasattr(item, "label")]
        self.assertIn("Toggle Dry-Run", labels)
        self.assertIn("Lockdown / Unlock", labels)
        self.assertIn("Raid Purge", labels)
        self.assertIn("Security Audit", labels)
        self.assertNotIn("Owner Bypasses", labels)

    def test_quarantine_control_view_structure(self):
        view = QuarantineControlView(self.bot, self.guild)
        view.stop()
        labels = [item.label for item in view.children if hasattr(item, "label")]
        self.assertIn("Quarantine Member", labels)
        self.assertIn("Unquarantine Member", labels)
        self.assertIn("Restore Lost Roles", labels)
        self.assertIn("View Quarantined List", labels)
        self.assertIn("Quarantine Setup", labels)

    def test_voice_control_view_structure(self):
        view = VoiceControlView(self.bot, self.guild)
        view.stop()
        labels = [item.label for item in view.children if hasattr(item, "label")]
        self.assertIn("Disconnect / Kick", labels)
        self.assertIn("Voice Timeout", labels)
        self.assertIn("Voice Ban", labels)
        self.assertIn("Active VC Bans List", labels)
        self.assertIn("Voice Guard (Toggle)", labels)

    def test_logs_control_view_structure(self):
        view = LogsControlView(self.bot, self.guild)
        view.stop()
        labels = [item.label for item in view.children if hasattr(item, "label")]
        self.assertIn("1-Click Setup (33 Channels)", labels)
        self.assertIn("Zero-Creation Sync", labels)
        self.assertIn("Clean Empty Logs", labels)

    def test_master_panel_view_dropdown(self):
        view = MasterPanelView(self.bot, self.guild, self.mod)
        view.stop()
        dropdowns = [item for item in view.children if isinstance(item, MasterDropdown)]
        self.assertEqual(len(dropdowns), 1)
        dd = dropdowns[0]
        values = [opt.value for opt in dd.options]
        self.assertIn("security", values)
        self.assertIn("quarantine", values)
        self.assertIn("voice", values)
        self.assertIn("logs", values)
        self.assertNotIn("bypasses", values)

    def test_modals_initialization(self):
        qm = QuarantineModal(self.bot)
        self.assertEqual(qm.title, "🔒 Quarantine Member")

        uqm = UnquarantineModal(self.bot)
        self.assertEqual(uqm.title, "🔓 Unquarantine & Restore Roles")

        rrm = RestoreRolesModal(self.bot)
        self.assertEqual(rrm.title, "♻️ Restore Lost Roles")

        vkm = VoiceKickModal(self.bot)
        self.assertEqual(vkm.title, "🔌 Voice Disconnect / Kick")

        vtm = VoiceTimeoutModal(self.bot)
        self.assertEqual(vtm.title, "🔇 Voice Channel Timeout")
        self.assertEqual(vtm.duration_input.default, "15")

        vbm = VoiceBanModal(self.bot)
        self.assertEqual(vbm.title, "⛔ Voice Channel Ban")

        lsm = LogSetupModal(self.bot)
        self.assertEqual(lsm.prefix_input.default, "𝚲")
        self.assertEqual(lsm.category_input.default, "𝚲 SERVER LOGS")

    def test_resolve_member_input(self):
        m1 = MagicMock(spec=discord.Member)
        m1.id = 111222333444555666
        m1.name = "shadow_raider"
        m1.global_name = "Shadow"
        m1.display_name = "Shadow [Raid]"

        self.guild.get_member.side_effect = lambda uid: m1 if uid == 111222333444555666 else None
        self.guild.members = [m1]

        def step_coro(coro):
            try:
                coro.send(None)
            except StopIteration as e:
                return e.value

        # 1. Plain ID
        res1 = step_coro(resolve_member_input(self.guild, "111222333444555666"))
        self.assertEqual(res1, m1)

        # 2. Mention format
        res2 = step_coro(resolve_member_input(self.guild, "<@111222333444555666>"))
        self.assertEqual(res2, m1)

        # 3. Nick mention format
        res3 = step_coro(resolve_member_input(self.guild, "<@!111222333444555666>"))
        self.assertEqual(res3, m1)

        # 4. Username format
        res4 = step_coro(resolve_member_input(self.guild, "shadow_raider"))
        self.assertEqual(res4, m1)

        # 5. Non-existent user
        res5 = step_coro(resolve_member_input(self.guild, "ghost_user_xyz"))
        self.assertIsNone(res5)


if __name__ == "__main__":
    unittest.main()

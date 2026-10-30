"""Configuration loader and manager for Discord Security Bot."""
import os
import yaml
import logging
from typing import Any, Dict, List, Optional, Set
import discord
from dotenv import load_dotenv

logger = logging.getLogger("security_bot.config")

# Load environment variables
load_dotenv()

# Complete Level Up Reward Roles Hierarchy
LEVEL_REWARDS_HIERARCHY = [
    (5, "Guild Recruit"),
    (10, "Bronze Rank"),
    (20, "Iron Rank"),
    (30, "Steel Rank"),
    (40, "Silver Rank"),
    (50, "Gold Rank"),
    (60, "Platinum Rank"),
    (70, "Emerald Rank"),
    (80, "Sapphire Rank"),
    (90, "Ruby Rank"),
    (100, "Diamond Rank"),
    (125, "Elite Rank"),
    (150, "Veteran Rank"),
    (175, "Master Rank"),
    (200, "Grand Rank"),
    (250, "Guild Hero"),
    (300, "Legendary Hero"),
    (350, "Dragonslayer"),
    (400, "Realm Champion"),
    (450, "Mythic Rank"),
    (500, "Guild Grandmaster"),
]

class BotConfig:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.raw_data: Dict[str, Any] = {}
        self.dynamic_bypass_roles: Set[int] = set()
        self.dynamic_bypass_users: Set[int] = set()
        self.dynamic_bypass_channels: Set[int] = set()
        self.guild_settings_cache: Dict[int, Dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Loads configuration from YAML file and environment."""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.raw_data = yaml.safe_load(f) or {}
            logger.info("Configuration loaded from %s", self.config_path)
        else:
            logger.warning("Config file %s not found. Using defaults.", self.config_path)
            self.raw_data = {}

        # Environment variable overrides
        self.discord_token = os.getenv("DISCORD_TOKEN", "")
        self.alert_channel_id = int(os.getenv("ALERT_CHANNEL_ID", "0"))
        self.guild_id = int(os.getenv("GUILD_ID", "0")) if os.getenv("GUILD_ID") else None
        self.owner_id = int(os.getenv("OWNER_ID", "0")) if os.getenv("OWNER_ID") else None
        self.health_port = int(os.getenv("HEALTH_PORT", "8080"))

    # General settings
    @property
    def dry_run(self) -> bool:
        return self.raw_data.get("general", {}).get("dry_run", True)

    @dry_run.setter
    def dry_run(self, value: bool) -> None:
        if "general" not in self.raw_data:
            self.raw_data["general"] = {}
        self.raw_data["general"]["dry_run"] = bool(value)

    @property
    def audit_retention_days(self) -> int:
        return int(self.raw_data.get("general", {}).get("audit_retention_days", 30))

    @property
    def log_level(self) -> str:
        return self.raw_data.get("general", {}).get("log_level", "INFO")

    # Progressive Trust (Level Gates)
    @property
    def progressive_trust(self) -> Dict[str, Any]:
        return self.raw_data.get("progressive_trust", {})

    # Raid detection settings
    @property
    def raid_detector(self) -> Dict[str, Any]:
        return self.raw_data.get("raid_detector", {})

    # Spam detection settings
    @property
    def spam_detector(self) -> Dict[str, Any]:
        return self.raw_data.get("spam_detector", {})

    # Phishing settings
    @property
    def phishing_detector(self) -> Dict[str, Any]:
        return self.raw_data.get("phishing_detector", {})

    # Lockdown settings
    @property
    def lockdown(self) -> Dict[str, Any]:
        return self.raw_data.get("lockdown", {})

    # Anti-Nuke settings
    @property
    def anti_nuke(self) -> Dict[str, Any]:
        return self.raw_data.get("anti_nuke", {})

    # Owner bypass validation
    def is_guild_owner(self, guild: Optional[discord.Guild], user_id: int) -> bool:
        """Checks if a user is the server owner or configured owner."""
        if self.owner_id and user_id == self.owner_id:
            return True
        if guild and guild.owner_id == user_id:
            return True
        return False

    def is_bypassed(self, guild: Optional[discord.Guild], member: discord.Member, channel: Optional[discord.abc.GuildChannel] = None) -> bool:
        """Determines if a member or channel is exempted from security rules by the owner."""
        if member.bot:
            return True  # Internal bots are handled or exempted if configured
        if self.is_guild_owner(guild, member.id):
            return True  # Server owner always bypasses

        # Check configured bypass users
        configured_users = self.raw_data.get("owner_bypasses", {}).get("users", [])
        if member.id in configured_users or member.id in self.dynamic_bypass_users:
            return True

        # Check configured bypass channels
        if channel:
            configured_channels = self.raw_data.get("owner_bypasses", {}).get("channels", [])
            if channel.id in configured_channels or channel.id in self.dynamic_bypass_channels:
                return True

        # Check configured bypass roles
        configured_roles = self.raw_data.get("owner_bypasses", {}).get("roles", [])
        member_role_ids = {r.id for r in member.roles}
        member_role_names = {r.name for r in member.roles}

        for role_entry in configured_roles:
            if isinstance(role_entry, int) and role_entry in member_role_ids:
                return True
            if isinstance(role_entry, str) and (role_entry in member_role_names or (role_entry.isdigit() and int(role_entry) in member_role_ids)):
                return True

        for dyn_role_id in self.dynamic_bypass_roles:
            if dyn_role_id in member_role_ids:
                return True

        return False

    def get_alert_channel_id(self, guild_id: Optional[int]) -> int:
        """Returns the alert channel ID for a specific guild, falling back to default."""
        if guild_id and guild_id in self.guild_settings_cache:
            custom_id = self.guild_settings_cache[guild_id].get("alert_channel_id")
            if custom_id:
                return int(custom_id)
        return self.alert_channel_id

    def get_log_channel_id(self, guild_id: Optional[int], category: str) -> Optional[int]:
        """Returns dedicated channel ID for category (chat, voice, member, mod, server), falling back to alert channel."""
        col = f"{category}_log_channel_id"
        if guild_id and guild_id in self.guild_settings_cache:
            ch_id = self.guild_settings_cache[guild_id].get(col)
            if ch_id:
                return int(ch_id)
        return None

    def is_dry_run(self, guild_id: Optional[int]) -> bool:
        """Returns the dry run status for a specific guild, falling back to default."""
        if guild_id and guild_id in self.guild_settings_cache:
            if "dry_run" in self.guild_settings_cache[guild_id]:
                return bool(self.guild_settings_cache[guild_id]["dry_run"])
        return self.dry_run

    def has_required_role(self, member: discord.Member, required_role_id_or_name: Any, gate_name: Optional[str] = None) -> bool:
        """Checks if a member has a specific role by ID or Name, respecting per-guild settings & hierarchy."""
        # If user is owner or bypassed, always true
        if member.guild and self.is_bypassed(member.guild, member):
            return True

        # Check if the guild has selected a custom role for this gate
        if gate_name and member.guild and member.guild.id in self.guild_settings_cache:
            g_cfg = self.guild_settings_cache[member.guild.id]
            custom_role_id = g_cfg.get(f"{gate_name}_role_id")
            if custom_role_id:
                # If member has the exact selected role
                if any(r.id == custom_role_id for r in member.roles):
                    return True
                # Check custom role name in level hierarchy
                custom_role_name = g_cfg.get(f"{gate_name}_role_name")
                if custom_role_name:
                    required_role_id_or_name = custom_role_name

        if not required_role_id_or_name:
            return True

        req_str = str(required_role_id_or_name).strip().lower()
        member_role_names = {r.name.lower() for r in member.roles}
        member_role_ids = {str(r.id) for r in member.roles}

        # Direct match by name or role ID
        if req_str in member_role_names or req_str in member_role_ids:
            return True

        # Hierarchical level check: If the required role is part of the level rewards,
        # having ANY higher level rank also grants permission!
        hierarchy_names = [name.lower() for (_, name) in LEVEL_REWARDS_HIERARCHY]
        if req_str in hierarchy_names:
            req_index = hierarchy_names.index(req_str)
            # All roles from req_index to the top of the hierarchy are permitted
            permitted_roles = set(hierarchy_names[req_index:])
            if member_role_names.intersection(permitted_roles):
                return True

        return False

    def save_yaml(self) -> None:
        """Persists current in-memory raw_data back to config.yaml."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(self.raw_data, f, default_flow_style=False, sort_keys=False)
            logger.info("Saved configuration updates to %s", self.config_path)
        except Exception as e:
            logger.error("Failed to save config file: %s", e)

# Singleton configuration instance
bot_config = BotConfig()

"""Interactive, beginner-friendly /help command cog.
Provides clear, human-understandable documentation and setup guides for public server owners.
"""
import discord
from discord import app_commands
from discord.ext import commands

HELP_PAGES = {
    "quickstart": {
        "title": "🚀 3-Step Setup Guide (Quickstart)",
        "color": discord.Color.blue(),
        "description": (
            "Welcome to **Antigravity Security**! In just 1 click, your server will be fully protected from join raids, scam links, and mic spam.\n\n"
            "### ⚡ Recommended: 1-Click Auto Setup\n"
            "Just type this single command:\n"
            "`/security auto_setup`\n"
            "The bot will automatically create a private **`🛡️ SECURITY & AUDIT SUITE`** category, create `#🚨-security-alerts` and all 5 log channels, and bind them all instantly!\n\n"
            "### Step 2: Connect Your Level Roles\n"
            "Select which level roles unlock links, GIFs, and voice channel mics:\n"
            "• `/security set_role gate:links role:@YourLevelRole` *(e.g. Level 5)*\n"
            "• `/security set_role gate:media role:@YourLevelRole` *(e.g. Level 5)*\n"
            "• `/security set_role gate:mic role:@YourLevelRole` *(e.g. Level 5)*\n\n"
            "### Step 3: Turn On Active Protection\n"
            "The bot starts in **Dry-Run Mode** (it alerts mods without punishing members so you can test).\n"
            "When you're ready for automatic protection, type:\n"
            "`/security toggle_dry_run`\n\n"
            "✅ *That's it! Your server is now guarded 24/7.*"
        )
    },
    "level_gates": {
        "title": "🔒 Progressive Trust (Level Role Gates)",
        "color": discord.Color.gold(),
        "description": (
            "### How Does This Stop 99% of Scammers?\n"
            "Scam bots and compromised accounts usually join a server and immediately post fake Nitro, Steam gift, or crypto links in chat.\n\n"
            "**Progressive Trust** solves this by gently locking high-risk perks behind earned level roles:\n"
            "• **Links & URLs**: New members cannot share external links until reaching your configured role.\n"
            "• **GIFs & Media**: Prevents unranked spam bots from flooding chat with memes or Tenor GIFs.\n"
            "• **ZIP / RAR Files**: Stops unknown accounts from distributing token-loggers.\n"
            "• **Discord Server Invites**: Stops rival servers from poaching your members.\n\n"
            "### 💡 Friendly Member Experience\n"
            "When a new member tries to post a link, the bot removes it and leaves a polite note:\n"
            "> *\"🔒 Links unlock at @LevelRole! Keep chatting to level up!\"*\n"
            "This note **auto-deletes after 6 seconds**, keeping your chat completely clean and drama-free.\n\n"
            "### 👑 Smart Level Inheritance\n"
            "Even if your leveling bot removes earlier roles when someone levels up to higher ranks (e.g. Level 50), the bot knows they are higher level and never removes their permissions."
        )
    },
    "voice_protection": {
        "title": "🎙️ Voice Channel & Microphone Protection",
        "color": discord.Color.purple(),
        "description": (
            "Voice channel raids are one of the most disruptive attacks on Discord. Here is how the bot defends your VCs:\n\n"
            "### 1. Microphone Gate (Anti-Ear Rape)\n"
            "• New or low-level members can freely join voice channels and **listen** to the conversation.\n"
            "• However, if they try to unmute their microphone before reaching your configured level role, the bot immediately server-mutes them.\n"
            "• A polite private DM is sent explaining how to unlock voice permissions.\n\n"
            "### 2. Anti-VC Hopping (Connect Sound Spam)\n"
            "• Attackers often rapidly join and leave voice channels to blast everyone's headphones with Discord join/disconnect chimes.\n"
            "• The bot detects rapid channel switching ($> 5$ switches in 10s), disconnects the user, and applies a 5-minute timeout.\n\n"
            "Configure your voice role with:\n"
            "`/security set_role gate:mic role:@YourRole`"
        )
    },
    "raid_scam": {
        "title": "🛡️ Raid, Scam & Malware Defenses",
        "color": discord.Color.red(),
        "description": (
            "The bot continuously monitors events in real-time to stop coordinated attacks:\n\n"
            "• 🚨 **Anti-Raid Join Tracker**: Flags sudden bursts of accounts joining in seconds, especially accounts created less than 24 hours ago.\n"
            "• 🛑 **Phishing & Brand Spoof Scanner**: Catches typosquatting like `discorcl-gift.com` or Cyrillic lookalikes mimicking Steam/Nitro.\n"
            "• 💬 **Spam Burst & Copypasta Limiter**: Stops wall-of-text flooding and identical text copy-pasted across channels.\n"
            "• ☣️ **Executable Blocker**: Instantly deletes `.exe`, `.scr`, `.bat`, `.apk`, and double-extension files (`photo.png.exe`).\n"
            "• 🤖 **Compromised Account Shield**: If a real friend's account gets hacked and starts sending *\"test my new game\"* token stealers, the bot quarantines the account for 1 hour to prevent damage.\n"
            "• 🏷️ **Zalgo / Screen-Lag Sanitizer**: Cleans invisible names or vertical screen-crashing text.\n"
            "• 🪓 **One-Click Raid Purge**: Use `/security purge_raid` to kick or ban a 50-bot raid wave in one click."
        )
    },
    "owner_controls": {
        "title": "👑 Server Owner Controls & Exemptions",
        "color": discord.Color.dark_gold(),
        "description": (
            "### The Server Owner Has Sole Authority\n"
            "To prevent rogue moderators or compromised bots from disabling security, **only the Server Owner** can manage exemptions.\n\n"
            "### Bypass Slash Commands (Owner Only):\n"
            "• `/security bypass add_role role:@Role` — Gives a role complete exemption from all security gates.\n"
            "• `/security bypass remove_role role:@Role` — Revokes an exemption.\n"
            "• `/security bypass add_user user:@User` — Exempts a specific trusted member.\n"
            "• `/security bypass add_channel channel:#channel` — Exempts a channel (e.g. staff room or bot-spam).\n"
            "• `/security bypass list` — Displays all active bypasses."
        )
    },
    "logging": {
        "title": "📑 Dedicated Audit & Activity Logs",
        "color": discord.Color.teal(),
        "description": (
            "Never wonder what happened on your server again. Every event is organized into separate, dedicated channels:\n\n"
            "### 💬 1. Chat Logs (`#chat-logs`)\n"
            "• **Message Deletions**: Shows who wrote it, channel, deleted text, and attachment filenames.\n"
            "• **Message Edits**: Shows Before vs After content with a direct jump link.\n\n"
            "### 🔊 2. Voice Logs (`#voice-logs`)\n"
            "• Records when members **join**, **leave**, or **switch** voice channels.\n"
            "• Records server mutes and deafens.\n\n"
            "### 👥 3. Member Logs (`#join-leave-logs`)\n"
            "• **Joins**: Shows exact account creation date and flags **⚠️ New Accounts (< 24h)**.\n"
            "• **Leaves**: Shows how long they were in the server and the roles they held.\n\n"
            "### 🔨 4. Mod Logs (`#mod-logs`)\n"
            "• Shows **who did what to whom** and the **exact reason**:\n"
            "  - Bans & Unbans (`@Mod banned @User`)\n"
            "  - Kicks (`@Mod kicked @User`)\n"
            "  - Timeouts (`@Mod timed out @User for 10m`)\n\n"
            "### 📁 5. Server Logs (`#server-logs`)\n"
            "• Channel and Role creations, deletions, and permission modifications.\n\n"
            "### ⚡ 1-Click Setup\n"
            "Type `/security setup_all_logs` to auto-create all 5 channels in a private category in seconds!"
        )
    },
    "commands": {
        "title": "📜 Complete Slash Command Reference",
        "color": discord.Color.teal(),
        "description": (
            "### Setup & Configuration\n"
            "• `/security auto_setup` — 1-Click: Creates private category with alerts + all 5 log channels and binds them instantly!\n"
            "• `/security set_role <gate> <role>` — Connect a level role to a security gate (`links`, `media`, `mic`, `archives`, `invites`).\n"
            "• `/security set_alert_channel <channel>` — Set the channel for mod alerts and raid cards.\n"
            "• `/security set_log_channel <category> <channel>` — Assign dedicated channel for specific log category.\n"
            "• `/security setup` — View current security configuration, level roles, and log channels.\n"
            "• `/security status` — Check bot health, active rules, and configured roles.\n"
            "• `/security toggle_dry_run` — Switch between Alert-Only (Testing) and Active Enforcement.\n\n"
            "### Moderation & Containment\n"
            "• `/security lockdown [duration] [reason]` — Temporarily lock all public channels with auto-expiration.\n"
            "• `/security unlock` — Manually lift a lockdown immediately.\n"
            "• `/security purge_raid [within_minutes] [action]` — Scan and purge a wave of raid accounts in one click.\n\n"
            "### Owner-Only Bypasses\n"
            "• `/security bypass add_role / remove_role` — Manage role exemptions.\n"
            "• `/security bypass add_user / remove_user` — Manage member exemptions.\n"
            "• `/security bypass add_channel / remove_channel` — Manage channel exemptions.\n"
            "• `/security bypass list` — View all exempt roles, users, and channels."
        )
    }
}

class HelpSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(
                label="3-Step Setup Guide",
                value="quickstart",
                description="Get your server protected in under 2 minutes",
                emoji="🚀",
                default=True
            ),
            discord.SelectOption(
                label="Level Gates & Rewards",
                value="level_gates",
                description="How link, media, and file permissions work",
                emoji="🔒"
            ),
            discord.SelectOption(
                label="Voice Channel & Mic Security",
                value="voice_protection",
                description="Stop ear-rape, mic screamers, and chime spam",
                emoji="🎙️"
            ),
            discord.SelectOption(
                label="Raid, Scam & Malware Defenses",
                value="raid_scam",
                description="Phishing, token stealers, and join raid shields",
                emoji="🛡️"
            ),
            discord.SelectOption(
                label="Server Owner Controls",
                value="owner_controls",
                description="How the owner keeps full authority and bypasses",
                emoji="👑"
            ),
            discord.SelectOption(
                label="Dedicated Audit & Activity Logs",
                value="logging",
                description="Chat, voice, join/leave, and mod logs (who did what)",
                emoji="📑"
            ),
            discord.SelectOption(
                label="Complete Command List",
                value="commands",
                description="Full list of all slash commands and options",
                emoji="📜"
            ),
        ]
        super().__init__(placeholder="Select a topic to explore...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        selected_key = self.values[0]
        page = HELP_PAGES.get(selected_key, HELP_PAGES["quickstart"])

        # Update default selected state
        for opt in self.options:
            opt.default = (opt.value == selected_key)

        embed = discord.Embed(
            title=page["title"],
            description=page["description"],
            color=page["color"]
        )
        embed.set_footer(text="Antigravity Security Suite • Use dropdown below to navigate")
        await interaction.response.edit_message(embed=embed, view=self.view)


class HelpView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(HelpSelect())


class SecurityHelp(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @app_commands.command(name="help", description="Learn how to configure and use Antigravity Security Bot.")
    async def cmd_help(self, interaction: discord.Interaction):
        page = HELP_PAGES["quickstart"]
        embed = discord.Embed(
            title=page["title"],
            description=page["description"],
            color=page["color"]
        )
        embed.set_footer(text="Antigravity Security Suite • Use dropdown below to navigate")
        view = HelpView()
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

async def setup(bot: commands.Bot):
    await bot.add_cog(SecurityHelp(bot))

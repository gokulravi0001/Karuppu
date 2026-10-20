# Discord Security Bot with Progressive Trust & Anti-Raid Defense

A security bot for Discord built with Python 3.11+ and `discord.py`. Designed to defend against join raids, phishing scams, spam bursts, mass mentions, and compromised accounts while maintaining a smooth, friendly member experience.

---

## 🌟 Key Features

1. **Progressive Trust (Tiered Permissions)**:
   * Restricts high-risk interactions (sending links, GIFs, media files, mic in VC, archive uploads) until members earn your server's **Level Reward Roles**.
   * **Smart Level Inheritance**: If a member levels up to higher ranks (e.g. `@Bronze Rank` or `@Gold Rank`), they automatically retain all previous perks even if your leveling bot removes earlier roles!
   * **Role Gating Defaults**:
     * **Level 5 (`@Guild Recruit`)**: Unlocks external Links, Tenor/Giphy GIFs, Media Attachments, and Microphone access in Voice Channels.
     * **Level 10 (`@Bronze Rank`)**: Unlocks `.zip` / `.rar` archive uploads and posting external Discord server invites.
   * Educates members with friendly, auto-deleting notices so channels stay clean.
2. **Owner-Exclusive Bypass Control**:
   * **No automated role exemptions**: Only the **Server Owner** has authority to designate who or what bypasses security filters.
   * Slash commands for adding/removing bypass roles, users, and channels are strictly locked to the Server Owner (`guild.owner_id == ctx.author.id`).
3. **Voice Channel & Mic Protection**:
   * **Microphone Progressive Trust Gate**: Restricts unmuting microphones in VC until members reach `Level 3` (or configured level role). Low-level accounts can still join and listen, but cannot mic spam or ear-rape conversations.
   * **VC Hopping / Notification Chime Spam**: Detects raid bots or users rapidly jumping between voice channels ($> 5$ transitions in 10s) to spam connect/disconnect sounds. Disconnects and temporarily times out the offender.
4. **Malicious Attachment & Executable Blocker**:
   * Blocks dangerous executables (`.exe`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.msi`, `.iso`, `.jar`, `.apk`) and double extensions (`.png.exe`).
   * Gates `.zip` / `.rar` archive uploads behind `Level 5`.
5. **Discord Invite Gate & Anti-Poaching**:
   * Resolves Discord invite codes (`discord.gg/...`); permits internal server invites, while external server promotions require `Level 10`.
6. **Compromised Account ("Hacked Friend") Shield**:
   * Detects hijacked accounts spreading fake game beta tests ("test my unity game"), tournament vote scams, or rapid multi-channel link dispersion.
   * Automatically isolates the account with a 1-hour containment timeout and alerts mods.
7. **Zalgo Text, Blank Names & Impersonation Sanitizer**:
   * Detects vertical combining unicode marks that crash/lag mobile Discord apps.
   * Renames invisible, zero-width names or users mimicking the Server Owner to `Moderated Nickname #XXXX`.
8. **Anti-Webhook Hijacking & Rogue Bot Guard**:
   * Detects leaked/compromised webhook URLs posting unauthorized `@everyone` or scam lures. Automatically deletes the webhook URL to permanently cut off attacker access.
9. **One-Click Rapid Raid Purge (`/security purge_raid`)**:
   * Allows staff to scan and purge/kick accounts that joined during a raid wave with interactive dry-run preview and confirmation modal.
10. **Anti-Raid Defense**:
   * Sliding-window velocity tracking for rapid join bursts ($\ge 5$ joins in 10s).
   * Flags suspicious accounts created $< 24$ hours ago.
   * Dispatches actionable mod cards with one-click containment: **Activate 15m Lockdown** or **Timeout Raid Accounts**.
11. **Phishing & Scam Link Scanner**:
   * Scans for typosquatting, Cyrillic/homoglyph lookalikes, and brand spoofing (`discord`, `nitro`, `steamcommunity`, etc.) using Levenshtein distance.
   * Allowlist for trusted platforms (`youtube.com`, `tenor.com`, `spotify.com`, etc.).
12. **Spam & Mass Mention Limiter**:
   * Token-bucket rate limiter for rapid bursts ($> 5$ messages in 4s).
   * Cross-channel duplicate/copypasta detector (ignores short chat like "gg", "lol").
   * Detects mass pings ($\ge 4$ mentions) and unauthorized `@everyone` / `@here`.
13. **Graduated Response & Safe Defaults**:
   * **Dry-Run Mode Enabled by Default** (`dry_run: true`): Alerts moderators with interactive action cards before taking any destructive action.
   * **Human Approval for High-Impact Actions**: Bans and mass actions require explicit moderator confirmation modals. The bot **never** automatically mass-bans.
14. **Emergency Auto-Expiring Lockdown**:
   * Reversible lockdown command (`/security lockdown duration:15m`) with automatic expiration to prevent permanent channel lockouts.
15. **Privacy-Preserving**:
   * Ephemeral in-memory sliding windows (60s TTL). Raw message content is never stored on disk; only SHA-256 hashes and truncated snippets are recorded.
   * Automatic daily audit log pruning based on configurable retention days.
16. **Dedicated Audit & Activity Logging Suite**:
   * Logs events into separate, dedicated channels so logs stay organized:
     * **Chat Logs** (`#chat-logs`): Message edits (Before vs After) and deletions with attachment filenames.
     * **Voice Logs** (`#voice-logs`): VC joins, leaves, channel switches, and server mute/deaf updates.
     * **Member Logs** (`#join-leave-logs`): Joins with exact account age & `⚠️ New Account (<24h)` badges, and leaves with duration stayed.
     * **Mod Logs** (`#mod-logs`): Who banned/kicked/timed out whom, expiration times, and exact reasons.
     * **Server Logs** (`#server-logs`): Channel and role creations/deletions.
   * **1-Click Auto Setup**: Run `/security setup_all_logs` to auto-create and bind all 5 channels in a private category in seconds!
17. **Docker & Healthcheck Ready**:
   * Multi-stage Dockerfile with non-root user execution (`botuser`) and internal HTTP healthcheck endpoint (`/health` on port 8080).

---

## 🚀 Quickstart & Setup Guide

### Prerequisites
* Docker and Docker Compose installed (or Python 3.11+)
* A Discord Bot Application created on the [Discord Developer Portal](https://discord.com/developers/applications)

### 1. Discord Developer Portal Setup
1. Navigate to **Discord Developer Portal** > **Applications** > **New Application**.
2. Go to the **Bot** tab:
   * Click **Reset Token** and copy your bot token.
   * Enable the following **Privileged Gateway Intents**:
     * ✅ **Server Members Intent** (Required for join raid tracking and account age audit)
     * ✅ **Message Content Intent** (Required for link scanner and spam heuristics)
3. Go to **OAuth2** > **URL Generator**:
   * **Scopes**: `bot`, `applications.commands`
   * **Bot Permissions** (Least Privilege):
     * `View Channels`
     * `Send Messages`
     * `Embed Links`
     * `Manage Messages` (For deleting spam/phishing messages)
     * `Moderate Members` (For applying temporary timeouts)
     * `Mute Members` (For server-muting unverified/low-level mic users in VC)
     * `Move Members` (For disconnecting VC hopping sound spammers)
     * `View Audit Log` (Required to show who banned/kicked/timed out whom in mod logs)
     * `Manage Channels` (Optional: allows `/security setup_all_logs` to auto-create log channels)
     * `Manage Roles` (Optional: only if using quarantine role)
     * `Ban Members` (For moderator-confirmed ban actions)
4. Copy the generated URL and invite the bot to your private test server.

---

### 2. Configuration & Secrets

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` with your values:
   ```ini
   DISCORD_TOKEN=your_bot_token_here
   ALERT_CHANNEL_ID=your_mod_log_channel_id
   GUILD_ID=your_test_server_id_optional
   OWNER_ID=your_discord_user_id_optional
   HEALTH_PORT=8080
   ```
3. Edit `config.yaml` to customize your level role names and thresholds:
   ```yaml
   progressive_trust:
     link_gate:
       required_role: "Level 5"     # Name or ID of your leveling role
     media_and_gif_gate:
       required_role: "Level 3"     # Name or ID of your leveling role
   ```

---

### 3. Running with Docker Compose (Recommended)

```bash
# Build and start the bot container in background
docker compose up -d --build

# View real-time logs
docker compose logs -f

# Check container health status
docker inspect --format='{{json .State.Health}}' discord-security-bot
```

### Running Locally (Without Docker)
```bash
pip install -r requirements.txt
python -m src.bot
```

---

## 🛠️ Slash Command Reference

### Server Owner-Only Commands
| Command | Description |
| :--- | :--- |
| `/security bypass add_role <role>` | Authorize a role to bypass all security gates. |
| `/security bypass remove_role <role>` | Revoke a role's security bypass. |
| `/security bypass add_user <user>` | Authorize a specific user to bypass all security gates. |
| `/security bypass remove_user <user>` | Revoke a user's security bypass. |
| `/security bypass add_channel <channel>` | Exempt a channel (e.g. staff lounge) from filters. |
| `/security bypass list` | Display all currently authorized bypasses. |

### Setup & Configuration (Admins & Staff)
| Command | Description |
| :--- | :--- |
| `/help` | Detailed, beginner-friendly guide with interactive topic dropdown. |
| `/security set_role <gate> <role>` | Select which level role unlocks a permission (`links`, `media`, `mic`, `archives`, `invites`). |
| `/security set_alert_channel <channel>` | Select the channel where raid cards and security alerts are posted. |
| `/security set_log_channel <category> <channel>` | Assign dedicated channels for `chat`, `voice`, `member`, `mod`, and `server` logs. |
| `/security setup_all_logs` | Auto-creates a private `📑 LOGS` category with all 5 log channels in 1 click! |
| `/security setup` | View current security configuration, level roles, and log channels. |
| `/security status` | Display active mode, latency, level gate rules, and health. |
| `/security toggle_dry_run` | Toggle between Dry-Run (Alert Only) and Active Enforcement. |

### Moderation & Containment
| Command | Description |
| :--- | :--- |
| `/security lockdown [duration] [reason]` | Lock public channels for N minutes (default 15m, auto-expiring). |
| `/security unlock` | Manually lift an active lockdown immediately. |
| `/security purge_raid [within_minutes] [require_no_roles] [action]` | Safe preview & 1-click purge of all accounts that joined during a raid wave. |

---

## 📁 Project Architecture

```
d:\Karrupan/
├── Dockerfile                  # Security-hardened multi-stage container
├── docker-compose.yml          # Container configuration with health checks
├── requirements.txt            # Python dependencies
├── config.yaml                 # Detection thresholds & progressive trust rules
├── .env.example                # Template for environment secrets
├── data/                       # Persistent directory (SQLite audit.db)
├── src/
│   ├── bot.py                  # Bot entry point, healthcheck & event router
│   ├── config.py               # YAML & env config manager with owner checks
│   ├── database.py             # SQLite structured audit logging & bypass store
│   └── cogs/
│       ├── trust_gate.py       # Progressive trust link & media/GIF gating
│       ├── raid_detector.py    # Sliding-window join burst tracker
│       ├── spam_detector.py    # Rate limiter, copypasta & mass ping filter
│       ├── link_filter.py      # Homoglyph & phishing URL scanner
│       ├── moderation_view.py  # Interactive Discord UI buttons & ban modals
│       ├── lockdown.py         # Auto-expiring emergency lockdown system
│       └── admin.py            # Owner bypass & operational slash commands
└── tests/
    └── test_detection.py       # Unit test suite for heuristics
```

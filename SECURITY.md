# Security Architecture, Threat Model & Testing Checklist

## 1. Threat Model & Matrix

| Threat Actor / Vector | Attack Description | Detection Heuristic | False Positive Mitigation | Defense Action |
| :--- | :--- | :--- | :--- | :--- |
| **Join Raid Botnet** | Mass simultaneous joins from user accounts to flood or disrupt the server. | Sliding window counts joins over 10s ($\ge 5$) & flags accounts $< 24$ hours old. | High-traffic public events (e.g., streamer shoutouts) can raise thresholds; owner bypasses apply. | Dry-run alert card with one-click **Lockdown (15m)** and **Mass Timeout (10m)**. |
| **Phishing / Account Compromise** | Compromised user or scam bot posts lookalike Nitro/Steam/Roblox gift links. | Levenshtein similarity ($\ge 82\%$) against protected brands + homoglyph normalization. | Extensive domain allowlist (`youtube.com`, `tenor.com`, `spotify.com`, etc.). | Auto-deletes message (in live mode) + 1h timeout + prompts mod to Ban. |
| **Spam / Channel Flooding** | User or self-bot spams rapid messages or walls of text. | Token-bucket burst check ($> 5$ msgs in 4s or $> 8$ msgs in 10s). | Owner-exempted channels (e.g., bot-commands or spam channels). | 5m auto-timeout in live mode; alert card in dry run. |
| **Copypasta / Cross-Channel Flooding** | User copies and pastes the same text repeatedly across multiple text channels. | SHA-256 hash ring buffer across 30s window ($\ge 4$ identical messages). | Ignores short messages ($< 10$ alphanumeric chars like "gg", "lol", reaction emojis). | Deletes subsequent messages + mod alert. |
| **Mass Mentions / Ping Abuse** | User tries to alert everyone or pings dozens of members. | Detects $\ge 4$ user/role pings in single message or unauthorized `@everyone`. | Ignores server staff with native permission. | Message deletion + timeout. |
| **Low-Level Link/Media Raiding** | Fresh raid accounts joining to post inappropriate GIFs or links. | Progressive Trust: Level role required for URLs (Level 5) and GIFs/Media (Level 3). | Chat-level progression gives genuine members rewards while neutralizing fresh bots. | Auto-deletes with a polite 6-second temporary educational hint. |
| **VC Mic Spam / Ear Rape** | Raid account or troll unmuting microphone in voice channels to scream, play ear-rape, or soundboard spam. | Progressive Trust Voice Gate: Inspects `on_voice_state_update`; flags unmuted mic if user lacks `Level 3` role. | Normal members can join & listen; microphone transmits freely once earned. Owner bypasses apply. | Server-mutes mic (in live mode) + friendly educational DM; alert card in dry run. |
| **VC Hopping / Chime Spam** | Bot or troll rapidly switching/joining VC channels to spam join/disconnect notification chimes. | Sliding window counts channel transitions over 10s ($> 5$ switches). | Normal channel movement is slow; owner bypasses exempt staff. | Disconnects member from VC + 5m timeout. |

---

## 2. Least-Privilege Discord Permissions Matrix

The bot requires **only** what is necessary to fulfill its defensive obligations. It avoids high-risk broad administrator permissions.

### Gateway Intents
* **`guilds`** (Standard): Required for guild structure, roles, and channel events.
* **`members`** (Privileged): Required for `on_member_join` to detect raid velocity and inspect account creation dates.
* **`messages`** (Standard): Required to monitor message events across channels.
* **`message_content`** (Privileged): Required to read message strings for scam URLs, mass pings, and copypasta.
* **`voice_states`** (Standard): Required to observe voice channel joins, unmuting events, and mic state changes.

### Guild Permissions
* **`View Channels`**: To read messages in monitored public channels.
* **`Send Messages` & `Embed Links`**: Strictly for posting alert cards and status reports in `#security-alerts`.
* **`Manage Messages`**: To delete confirmed phishing scams and spam bursts.
* **`Moderate Members`**: To apply reversible temporary timeouts (e.g. 5m, 10m).
* **`Mute Members`**: To server-mute unverified/low-level mic users in voice channels until level roles are earned.
* **`Move Members`**: To disconnect VC hopping sound spammers.
* **`View Audit Log`**: Required to inspect who banned, kicked, or timed out a member for moderator activity logs.
* **`Manage Channels`** *(Optional)*: Allows `/security setup_all_logs` to auto-create dedicated log channels.
* **`Manage Roles`** *(Optional)*: If the server uses a dedicated "Quarantined" role during raids. The bot's role must be positioned below moderators.
* **`Ban Members`** *(Human-Gated)*: Executed **only** when a human moderator clicks the confirmation modal.

---

## 3. False-Positive Considerations & Member-Friendly Philosophy

1. **No Public Accusations**:
   * The bot never brands a member as a "hacker" or "scammer" in public channels.
   * Educational messages for level gates (e.g., *"Links unlock at Level 5!"*) auto-delete after 6 seconds so regular chat remains clean and welcoming.
2. **Reversible Actions**:
   * Initial automated responses are strictly temporary (e.g., 5-minute timeout).
   * Irreversible actions (bans, permanent kicks) require explicit human confirmation.
3. **Owner-Exclusivity on Bypasses**:
   * Server owners can immediately exempt trusted bots (e.g., Carl-bot, Dyno, Mee6), specific moderator roles, or dedicated bot-command channels.
4. **Dry-Run Mode**:
   * Allows server leadership to test detection thresholds in live traffic without any member interruption.

---

## 4. Privacy & Data Minimization

* **No Persistent Message Content**: Raw message bodies are kept in an in-memory ring buffer with a 60-second TTL. Once a message is verified safe, it is discarded from memory.
* **Cryptographic Evidence**: In incident logs, message content is represented by a SHA-256 hash and a 60-character truncated snippet for moderator verification.
* **Automated Retention Pruning**: Incident records older than `audit_retention_days` (default: 30 days) are automatically deleted via a daily SQLite maintenance cycle.
* **Zero Cloud Data Sharing**: All audit data resides locally in `data/audit.db` on your host or container volume.

---

## 5. Private Test Server Checklist

Before deploying the bot into your production server, follow this checklist in a private test Discord server:

- [ ] **Step 1: Test Server Preparation**
  * Create a private test Discord server.
  * Create an `#alerts` or `#mod-logs` channel.
  * Create test roles matching your level rewards: `Guild Recruit` (Level 5) and `Bronze Rank` (Level 10).
- [ ] **Step 2: Bot Invitation & Configuration**
  * Generate the bot invite with `bot` and `applications.commands` scopes.
  * Invite the bot to the test server.
  * Put the bot's role above member roles, but below your Server Owner role.
  * Copy `.env.example` to `.env` and set `ALERT_CHANNEL_ID` and `DISCORD_TOKEN`.
- [ ] **Step 3: Verification of Dry-Run Mode**
  * Launch the bot (`python -m src.bot` or `docker compose up -d`).
  * Run `/security status` and confirm operational mode is `DRY RUN`.
- [ ] **Step 4: Test Progressive Trust (Level Gates)**
  * As a test user (or alternate account without `Level 5`), post a link (e.g. `https://example.com`).
  * Verify an incident alert is sent to `#alerts` with interactive buttons.
  * Assign the `Level 5` role to the account; verify posting links is now permitted.
- [ ] **Step 5: Test Phishing Detection**
  * Post a simulated spoof domain: `https://discorcl-nitro.com/gift`.
  * Verify the bot catches the Levenshtein brand spoof and alerts with high confidence.
- [ ] **Step 6: Test Spam & Mass Mentions**
  * Post 6 rapid messages in under 4 seconds.
  * Verify the rapid burst alert fires.
  * Mention 4 users in one message; verify mass mention alert fires.
- [ ] **Step 7: Test Moderator UI Buttons**
  * On an alert card in `#alerts`, test clicking `Dismiss (False Positive)` and verify the card marks as dismissed.
  * Test clicking `Timeout (10m)` and verify timeout is applied to the member.
  * Test clicking `Ban Account...` and verify the modal requires typing `CONFIRM`.
- [ ] **Step 8: Test Emergency Lockdown**
  * Run `/security lockdown duration:2 reason:"Test lockdown"`.
  * Verify `@everyone` cannot send messages in public channels.
  * Run `/security unlock` or wait 2 minutes to confirm auto-restoration.
- [ ] **Step 9: Test Voice Channel & Mic Protection**
  * Join a test Voice Channel with an account lacking `Level 3` and unmute the microphone.
  * In dry run: Verify an alert card appears in `#alerts` (`VC Mic Access Violation`).
  * In live enforcement: Verify the bot server-mutes the account and sends the educational DM.
  * Rapidly switch voice channels 5 times in 10s; verify hopping alert/timeout triggers.
- [ ] **Step 10: Test Owner Bypass**
  * Have the server owner run `/security bypass add_role @Role`.
  * Verify members with that role can post links and speak in VC regardless of level.
- [ ] **Step 11: Toggle Live Enforcement**
  * Run `/security toggle_dry_run` when satisfied with threshold accuracy!

# Privacy Policy for Karuppu Security Bot

**Effective Date:** November 4, 2026  
**Last Updated:** November 4, 2026  
**Application Name:** KARUPPU#6577  
**Application ID:** `1560663818353381467`  
**Public Website / Dashboard:** [https://karuppu-bot-frankfurt.onrender.com](https://karuppu-bot-frankfurt.onrender.com)  
**Hosted Privacy Policy URL:** [https://karuppu-bot-frankfurt.onrender.com/privacy](https://karuppu-bot-frankfurt.onrender.com/privacy)  
**Hosted Terms URL:** [https://karuppu-bot-frankfurt.onrender.com/terms](https://karuppu-bot-frankfurt.onrender.com/terms)  

---

## 1. Overview & Privacy-by-Design
This Privacy Policy explains how **Karuppu Security Bot** ("Karuppu", "we", "us", or "our", Application ID: `1560663818353381467`) collects, processes, and protects data when operating in your Discord servers or via its web dashboard.

Karuppu is designed around **Privacy-by-Design** principles. We collect and retain only the minimal operational data required to detect raids, filter scam links, prevent spam, and deliver real-time server activity logs. We do not conduct user profiling, mass surveillance, or commercial exploitation of your data.

---

## 2. Information We Collect

### A. Discord Platform Identifiers
- **User IDs, Server (Guild) IDs, Channel IDs, Role IDs**: Essential public Discord snowflake identifiers required to identify administrative contexts, deliver logging embeds to designated channels, and evaluate role permissions.

### B. Account Timestamps & Join History
- **Account Creation Date & Server Join Date**: Processed strictly to determine account age and join velocity during raid wave events and to assign progressive trust roles.

### C. Voice State & Audit Log Events
- **Voice States**: Information regarding voice channel joins, leaves, moves, server mute/deafen actions, and video/screenshare toggling.
- **Audit Events**: Server-level administrative actions (such as channel overwrite permission modifications, role changes, and nickname updates).
- *These events are formatted in real-time and dispatched directly to your guild's designated private log channels.*

### D. Ephemeral In-Memory Scanning (Zero Persistent Message Storage)
- **Safe Messages Are Never Stored**: Standard chat messages are evaluated ephemerally in RAM using a sliding-window buffer with a strict **60-second Time-To-Live (TTL)**. Harmless messages are purged from memory after analysis and are **never** written to disk or stored in any persistent database.

### E. Cryptographic Incident Records
- When an active malicious payload is flagged (e.g., known phishing link or suspicious executable), only a one-way **SHA-256 hash** and a short truncated excerpt (maximum 60 characters) are stored in incident audit records for administrator review.

---

## 3. Data Retention & Automated Pruning
We enforce strict data minimization and automatic retention pruning:
- **Temporary In-Memory Buffers**: Automatically discarded every 60 seconds.
- **Incident & Audit Records**: Stored in a secured local SQLite database and subject to an **automated 30-day retention pruning job**. Records older than 30 days are permanently purged.
- **Server Configurations**: Retained only while the bot is an active member of your server.

---

## 4. Zero Data Selling & Third-Party Sharing
**We never sell, rent, monetize, or lease user or server data to any third party.**
- We do not share data with advertising networks, third-party analytics firms, or data brokers.
- We do not use your data for marketing, advertising, or automated profiling.

---

## 5. Security & Infrastructure
Karuppu operates on secured containerized infrastructure with strict least-privilege security controls:
- Communications between Discord, the bot, and the web dashboard are encrypted in transit via HTTPS / TLS.
- Web dashboard sessions utilize cryptographically signed tokens.
- Persistent databases are isolated and accessible only by the bot process.

---

## 6. User Rights & Data Deletion (GDPR & CCPA Compliance)
You have complete control over your data:
- **Revoking Access**: Kicking or removing Karuppu from your server halts all data collection immediately.
- **Data Deletion Requests**: Server owners or individual users may request complete deletion of their stored server configuration and incident logs at any time by opening a request on our [GitHub Issues](https://github.com/gokulravi0001/Karuppu/issues) page or contacting the project developer. Requests are processed within 48 hours.

---

## 7. Children's Privacy
Karuppu complies with Discord's minimum age requirements and is not directed to individuals under 13 years of age (or the legal minimum age in your jurisdiction).

---

## 8. Contact & Privacy Requests
For questions, concerns, or data deletion requests regarding this Privacy Policy:
- **Application:** KARUPPU#6577 (`1560663818353381467`)
- **GitHub Repository:** [https://github.com/gokulravi0001/Karuppu](https://github.com/gokulravi0001/Karuppu)
- **Issue Tracker:** [https://github.com/gokulravi0001/Karuppu/issues](https://github.com/gokulravi0001/Karuppu/issues)

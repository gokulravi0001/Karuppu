# 🛡️ Karuppu Security Web Dashboard (Wick Alternative)

A modern, intuitive, and clean web dashboard for Discord server security, anti-nuke management, quarantine vault, and real-time audit logging. Designed to be **simpler, faster, and more powerful than Wick Bot's complex menus**.

---

## ⚡ Quick Start

### 1. Run Locally in 5 Seconds
Run the built-in python server:
```bash
python serve_dashboard.py
```
Open **[http://localhost:8080](http://localhost:8080)** in your browser (or simply double-click `web/index.html` to open directly!).

---

## 🗄️ Setting Up Free Firebase / Firestore Database

The dashboard works out-of-the-box in **Demo Mode**, but you can connect it to your free Google Firebase Firestore database in under 2 minutes:

1. Go to **[https://console.firebase.google.com](https://console.firebase.google.com)** and sign in with any Google account.
2. Click **Create a project** (Enter a project name e.g. `karuppu-security`).
3. Click **Build** $\rightarrow$ **Firestore Database** $\rightarrow$ **Create database** (Choose *Start in test mode* and select your nearest region).
4. Go to **Project Settings** (gear icon) $\rightarrow$ **General** $\rightarrow$ scroll down to **Your apps** and click the Web `</>` icon.
5. Register the app (no hosting needed), and copy the `firebaseConfig` snippet:
   ```json
   {
     "apiKey": "AIzaSy...",
     "authDomain": "your-project.firebaseapp.com",
     "projectId": "your-project",
     "storageBucket": "your-project.appspot.com",
     "messagingSenderId": "...",
     "appId": "..."
   }
   ```
6. On the web dashboard, click the **Database Icon** in the top navigation bar, paste this JSON, and click **Connect & Synchronize**.

---

## 🌟 Key Features vs Wick Bot

| Feature | Wick Bot (`wickbot.com`) | Karuppu Dashboard |
| :--- | :--- | :--- |
| **User Interface** | Cluttered, confusing sub-menus | Single-page, sleek cyberpunk dark mode |
| **Quarantine Management** | Complicated multi-step setup | 1-Click Role Restoration & Vault view |
| **Panic Mode** | Buried in commands | High-visibility 1-click emergency lockdown |
| **Free Database** | Paywalled tier limits | 100% Free Google Firestore Real-Time Sync |
| **Anti-Nuke Rate Limits** | Rigid defaults | Interactive sliders for bans, kicks & channels |
| **Audit Logs** | Slow manual refresh | Live real-time event stream (`onSnapshot`) |

---

## 🚀 Free Hosting Options
You can host this static dashboard 100% free with 0 server costs on:
- **GitHub Pages** (Settings $\rightarrow$ Pages $\rightarrow$ select `main` branch `/web` folder)
- **Vercel** (`vercel deploy web`)
- **Netlify** (Drag-and-drop the `web` folder)

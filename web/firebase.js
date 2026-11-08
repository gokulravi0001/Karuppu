/**
 * Karuppu / Wick-Style Security Dashboard - Firebase Integration
 * Connects to Google Cloud Firebase & Firestore (Free Tier)
 */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { 
    getFirestore, 
    collection, 
    doc, 
    setDoc, 
    getDoc, 
    getDocs, 
    onSnapshot, 
    query, 
    orderBy, 
    limit, 
    deleteDoc 
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

// Default / Stored configuration
const STORAGE_KEY = "karuppu_firebase_config";

// Mock Fallback Data when Firebase is not yet connected
export const MOCK_DATA = {
    guild: {
        id: "123456789012345678",
        name: "ChukkaVerse",
        icon: "https://cdn.discordapp.com/embed/avatars/0.png",
        memberCount: 1420,
        securityScore: 92,
        panicMode: false,
        settings: {
            anti_nuke: {
                enabled: true,
                max_bans_per_minute: 3,
                max_kicks_per_minute: 5,
                max_channel_deletions: 2,
                max_role_deletions: 2
            },
            quarantine: {
                role_name: "Quarantined",
                category_name: "🔒 Quarantine Zone",
                auto_isolate_channels: true
            },
            joingate: {
                min_account_age_days: 7,
                require_avatar: true,
                captcha_enabled: true
            }
        }
    },
    quarantine: [
        {
            id: "user_1",
            userId: "987654321098765432",
            username: "RogueAttacker#0001",
            avatar: "https://cdn.discordapp.com/embed/avatars/1.png",
            quarantinedAt: new Date(Date.now() - 3600000).toISOString(),
            reason: "Excessive channel deletion attempt (Triggered Anti-Nuke)",
            savedRoles: ["Staff", "Event Host", "Member"],
            quarantinedBy: "Karuppu Security Engine"
        },
        {
            id: "user_2",
            userId: "876543210987654321",
            username: "SuspiciousBot_v2",
            avatar: "https://cdn.discordapp.com/embed/avatars/2.png",
            quarantinedAt: new Date(Date.now() - 14400000).toISOString(),
            reason: "Rapid webhook creation & mention spam",
            savedRoles: ["Member"],
            quarantinedBy: "Karuppu AutoMod"
        }
    ],
    incidents: [
        {
            id: "inc_1",
            type: "MASS_CHANNEL_DELETE",
            severity: "CRITICAL",
            timestamp: new Date(Date.now() - 3600000).toISOString(),
            user: "RogueAttacker#0001",
            action: "Stripped roles & quarantined user",
            confidence: "99.4%"
        },
        {
            id: "inc_2",
            type: "RAID_FIREWALL_BLOCK",
            severity: "HIGH",
            timestamp: new Date(Date.now() - 7200000).toISOString(),
            user: "AltUser_9921",
            action: "Kicked (Account age < 7 days)",
            confidence: "100%"
        },
        {
            id: "inc_3",
            type: "SUSPICIOUS_WEBHOOK_CREATED",
            severity: "MEDIUM",
            timestamp: new Date(Date.now() - 14400000).toISOString(),
            user: "SuspiciousBot_v2",
            action: "Webhook deleted, member quarantined",
            confidence: "94.8%"
        },
        {
            id: "inc_4",
            type: "ROLES_RESTORED",
            severity: "INFO",
            timestamp: new Date(Date.now() - 28800000).toISOString(),
            user: "Gokul",
            action: "Roles restored by Server Owner",
            confidence: "100% (Admin Action)"
        }
    ]
};

class FirebaseService {
    constructor() {
        this.app = null;
        this.db = null;
        this.isLive = false;
        this.listeners = [];
        this.init();
    }

    init() {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try {
                const config = JSON.parse(stored);
                if (config.apiKey && config.projectId) {
                    this.connect(config);
                }
            } catch (e) {
                console.error("Error reading saved Firebase config:", e);
            }
        }
    }

    connect(config) {
        try {
            this.app = initializeApp(config);
            this.db = getFirestore(this.app);
            this.isLive = true;
            localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
            console.log("🔥 Connected live to Firebase Firestore:", config.projectId);
            return { success: true };
        } catch (e) {
            console.error("Firebase connection error:", e);
            this.isLive = false;
            return { success: false, error: e.message };
        }
    }

    disconnect() {
        this.unsubscribeAll();
        this.app = null;
        this.db = null;
        this.isLive = false;
        localStorage.removeItem(STORAGE_KEY);
    }

    getConfig() {
        const stored = localStorage.getItem(STORAGE_KEY);
        return stored ? JSON.parse(stored) : null;
    }

    unsubscribeAll() {
        this.listeners.forEach(unsub => unsub && unsub());
        this.listeners = [];
    }

    // Server Settings Sync
    async getSettings(guildId) {
        if (!this.isLive) {
            const local = localStorage.getItem(`karuppu_settings_${guildId}`);
            return local ? JSON.parse(local) : MOCK_DATA.guild.settings;
        }
        try {
            const ref = doc(this.db, "guild_settings", guildId);
            const snap = await getDoc(ref);
            if (snap.exists()) return snap.data();
            await setDoc(ref, MOCK_DATA.guild.settings);
            return MOCK_DATA.guild.settings;
        } catch (err) {
            console.warn("Firestore read failed, using fallback:", err);
            return MOCK_DATA.guild.settings;
        }
    }

    async saveSettings(guildId, settings) {
        if (!this.isLive) {
            localStorage.setItem(`karuppu_settings_${guildId}`, JSON.stringify(settings));
            return true;
        }
        try {
            const ref = doc(this.db, "guild_settings", guildId);
            await setDoc(ref, settings, { merge: true });
            return true;
        } catch (err) {
            console.error("Firestore save error:", err);
            return false;
        }
    }

    // Real-Time Quarantined Members Listener
    subscribeQuarantine(guildId, callback) {
        if (!this.isLive) {
            const local = localStorage.getItem(`karuppu_quarantine_${guildId}`);
            callback(local ? JSON.parse(local) : MOCK_DATA.quarantine);
            return () => {};
        }

        const qRef = collection(this.db, `guilds/${guildId}/quarantine`);
        const unsub = onSnapshot(qRef, (snapshot) => {
            const items = [];
            snapshot.forEach(docSnap => items.push({ id: docSnap.id, ...docSnap.data() }));
            callback(items);
        }, (err) => {
            console.warn("Quarantine subscription error:", err);
            callback(MOCK_DATA.quarantine);
        });

        this.listeners.push(unsub);
        return unsub;
    }

    // Release / Unquarantine Member
    async releaseMember(guildId, userId) {
        if (!this.isLive) {
            const local = localStorage.getItem(`karuppu_quarantine_${guildId}`);
            let list = local ? JSON.parse(local) : [...MOCK_DATA.quarantine];
            list = list.filter(item => item.userId !== userId && item.id !== userId);
            localStorage.setItem(`karuppu_quarantine_${guildId}`, JSON.stringify(list));
            return true;
        }
        try {
            const qRef = doc(this.db, `guilds/${guildId}/quarantine`, userId);
            await deleteDoc(qRef);
            return true;
        } catch (err) {
            console.error("Failed to delete quarantine record:", err);
            return false;
        }
    }

    // Real-Time Incidents Feed Listener
    subscribeIncidents(guildId, callback) {
        if (!this.isLive) {
            const local = localStorage.getItem(`karuppu_incidents_${guildId}`);
            callback(local ? JSON.parse(local) : MOCK_DATA.incidents);
            return () => {};
        }

        const incRef = collection(this.db, `guilds/${guildId}/incidents`);
        const q = query(incRef, orderBy("timestamp", "desc"), limit(20));
        const unsub = onSnapshot(q, (snapshot) => {
            const items = [];
            snapshot.forEach(docSnap => items.push({ id: docSnap.id, ...docSnap.data() }));
            callback(items.length ? items : MOCK_DATA.incidents);
        }, (err) => {
            console.warn("Incidents subscription error:", err);
            callback(MOCK_DATA.incidents);
        });

        this.listeners.push(unsub);
        return unsub;
    }

    // Log new incident
    async logIncident(guildId, incident) {
        if (!this.isLive) {
            const local = localStorage.getItem(`karuppu_incidents_${guildId}`);
            const list = local ? JSON.parse(local) : [...MOCK_DATA.incidents];
            list.unshift({ id: `inc_${Date.now()}`, ...incident });
            localStorage.setItem(`karuppu_incidents_${guildId}`, JSON.stringify(list.slice(0, 50)));
            return true;
        }
        try {
            const incRef = doc(collection(this.db, `guilds/${guildId}/incidents`));
            await setDoc(incRef, { ...incident, timestamp: new Date().toISOString() });
            return true;
        } catch (err) {
            console.error("Failed to log incident:", err);
            return false;
        }
    }
}

export const firebaseService = new FirebaseService();

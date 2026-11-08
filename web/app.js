/**
 * Karuppu Security Web Dashboard - Main Application Controller
 * Handles UI interactions, Tab Navigation, Realtime Firebase Sync & Settings
 */

import { firebaseService, MOCK_DATA } from './firebase.js';

// Active Guild State
let currentGuildId = "123456789012345678";
let currentSettings = { ...MOCK_DATA.guild.settings };
let activeQuarantineList = [];
let activeIncidentsList = [];

// Initialize Dashboard
document.addEventListener("DOMContentLoaded", async () => {
    // 1. Initialize Lucide Icons
    if (window.lucide) {
        window.lucide.createIcons();
    }

    // 2. Setup Tab Switching
    setupTabNavigation();

    // 3. Setup Range Sliders & Indicators
    setupSliders();

    // 4. Update Firebase Connection UI
    updateDbStatusPill();

    // 5. Load Guild Settings
    await loadSettings();

    // 6. Subscribe to Real-Time Data Streams
    setupRealtimeSubscriptions();

    // 7. Setup Panic Mode Button Listener
    setupPanicButton();
});

// Tab Navigation Controller
function setupTabNavigation() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetTab = tab.getAttribute("data-tab");
            
            // Highlight active tab
            tabs.forEach(t => {
                t.classList.remove("bg-discord", "text-white", "shadow-lg", "shadow-discord/20");
                t.classList.add("text-slate-400");
            });
            tab.classList.remove("text-slate-400");
            tab.classList.add("bg-discord", "text-white", "shadow-lg", "shadow-discord/20");

            // Show selected view
            document.querySelectorAll(".tab-content").forEach(content => {
                content.classList.add("hidden");
            });
            const activeView = document.getElementById(`tab-${targetTab}`);
            if (activeView) {
                activeView.classList.remove("hidden");
            }
        });
    });
}

// Sliders and Value Displays
function setupSliders() {
    const linkSlider = (sliderId, valId, suffix = "") => {
        const slider = document.getElementById(sliderId);
        const display = document.getElementById(valId);
        if (slider && display) {
            slider.addEventListener("input", (e) => {
                display.innerText = `${e.target.value}${suffix}`;
                recalculateSecurityScore();
            });
        }
    };

    linkSlider("slider-bans", "val-bans");
    linkSlider("slider-kicks", "val-kicks");
    linkSlider("slider-channels", "val-channels");
    linkSlider("slider-roles", "val-roles");
    linkSlider("slider-age", "val-age", " Days");
}

// Calculate dynamic health score
function recalculateSecurityScore() {
    let score = 70;
    const antiBan = document.getElementById("toggle-anti-ban")?.checked;
    const antiKick = document.getElementById("toggle-anti-kick")?.checked;
    const antiChannel = document.getElementById("toggle-anti-channel")?.checked;
    const antiRole = document.getElementById("toggle-anti-role")?.checked;
    const avatarReq = document.getElementById("toggle-avatar")?.checked;
    const captcha = document.getElementById("toggle-captcha")?.checked;

    if (antiBan) score += 6;
    if (antiKick) score += 6;
    if (antiChannel) score += 8;
    if (antiRole) score += 5;
    if (avatarReq) score += 2;
    if (captcha) score += 3;

    score = Math.min(score, 100);

    const metricScore = document.getElementById("metric-score");
    const sidebarScore = document.getElementById("sidebar-score");
    const sidebarScoreBar = document.getElementById("sidebar-score-bar");

    if (metricScore) metricScore.innerText = score;
    if (sidebarScore) sidebarScore.innerText = `${score}%`;
    if (sidebarScoreBar) sidebarScoreBar.style.width = `${score}%`;
}

// Load and populate settings
async function loadSettings() {
    currentSettings = await firebaseService.getSettings(currentGuildId);

    // Populate Anti-nuke
    if (currentSettings.anti_nuke) {
        setSliderVal("slider-bans", "val-bans", currentSettings.anti_nuke.max_bans_per_minute || 3);
        setSliderVal("slider-kicks", "val-kicks", currentSettings.anti_nuke.max_kicks_per_minute || 5);
        setSliderVal("slider-channels", "val-channels", currentSettings.anti_nuke.max_channel_deletions || 2);
        setSliderVal("slider-roles", "val-roles", currentSettings.anti_nuke.max_role_deletions || 2);
    }

    // Populate Joingate
    if (currentSettings.joingate) {
        setSliderVal("slider-age", "val-age", currentSettings.joingate.min_account_age_days || 7, " Days");
        setToggleVal("toggle-avatar", currentSettings.joingate.require_avatar !== false);
        setToggleVal("toggle-captcha", currentSettings.joingate.captcha_enabled !== false);
    }

    recalculateSecurityScore();
}

function setSliderVal(id, valId, val, suffix = "") {
    const el = document.getElementById(id);
    const disp = document.getElementById(valId);
    if (el) el.value = val;
    if (disp) disp.innerText = `${val}${suffix}`;
}

function setToggleVal(id, checked) {
    const el = document.getElementById(id);
    if (el) el.checked = checked;
}

// Save settings to Firebase / local
window.saveDashboardSettings = async function () {
    const settings = {
        anti_nuke: {
            enabled: true,
            max_bans_per_minute: parseInt(document.getElementById("slider-bans")?.value || 3),
            max_kicks_per_minute: parseInt(document.getElementById("slider-kicks")?.value || 5),
            max_channel_deletions: parseInt(document.getElementById("slider-channels")?.value || 2),
            max_role_deletions: parseInt(document.getElementById("slider-roles")?.value || 2),
            anti_ban_active: document.getElementById("toggle-anti-ban")?.checked,
            anti_kick_active: document.getElementById("toggle-anti-kick")?.checked,
            anti_channel_active: document.getElementById("toggle-anti-channel")?.checked,
            anti_role_active: document.getElementById("toggle-anti-role")?.checked
        },
        joingate: {
            min_account_age_days: parseInt(document.getElementById("slider-age")?.value || 7),
            require_avatar: document.getElementById("toggle-avatar")?.checked,
            captcha_enabled: document.getElementById("toggle-captcha")?.checked
        }
    };

    const ok = await firebaseService.saveSettings(currentGuildId, settings);
    if (ok) {
        showToast("Settings successfully synchronized to database!", "success");
    } else {
        showToast("Failed to save settings. Please verify database permissions.", "error");
    }
};

// Real-Time Quarantine & Incidents Sync
function setupRealtimeSubscriptions() {
    // 1. Quarantine Vault
    firebaseService.subscribeQuarantine(currentGuildId, (records) => {
        activeQuarantineList = records;
        renderQuarantineCards(records);
    });

    // 2. Incident Audit Stream
    firebaseService.subscribeIncidents(currentGuildId, (incidents) => {
        activeIncidentsList = incidents;
        renderIncidentStream(incidents);
    });
}

// Render Quarantined Cards with 1-Click Role Restoration
function renderQuarantineCards(records) {
    const grid = document.getElementById("quarantine-grid");
    const countBadge = document.getElementById("badge-quarantine-count");
    const metricCount = document.getElementById("metric-quarantine-count");

    if (countBadge) countBadge.innerText = records.length;
    if (metricCount) metricCount.innerText = records.length;

    if (!grid) return;

    if (!records || records.length === 0) {
        grid.innerHTML = `
            <div class="col-span-full py-12 text-center text-slate-400 space-y-2">
                <i data-lucide="shield-check" class="w-10 h-10 text-success mx-auto"></i>
                <p class="font-bold text-white">Quarantine Vault is Empty</p>
                <p class="text-xs">No users currently require isolation in this server.</p>
            </div>
        `;
        if (window.lucide) window.lucide.createIcons();
        return;
    }

    grid.innerHTML = records.map(item => `
        <div class="glass-panel p-5 rounded-2xl border border-borderBase hover:border-danger/40 transition space-y-4">
            <div class="flex items-start justify-between">
                <div class="flex items-center space-x-3">
                    <img src="${item.avatar || 'https://cdn.discordapp.com/embed/avatars/0.png'}" class="w-11 h-11 rounded-full border border-danger/40" alt="Avatar">
                    <div>
                        <h4 class="font-bold text-sm text-white">${item.username || 'User'}</h4>
                        <p class="text-[11px] font-mono text-slate-400">ID: ${item.userId || item.id}</p>
                    </div>
                </div>
                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-danger/15 text-danger border border-danger/30 uppercase">
                    ISOLATED
                </span>
            </div>

            <div class="text-xs space-y-1.5 bg-darker/60 p-3 rounded-xl border border-borderBase">
                <p class="text-slate-300"><b class="text-slate-400">Reason:</b> ${item.reason || 'Security threat detected'}</p>
                <p class="text-slate-400"><b class="text-slate-400">Staff:</b> ${item.quarantinedBy || 'Karuppu Bot'}</p>
                <p class="text-slate-400"><b class="text-slate-400">Backed-up Roles:</b> <span class="text-discord font-medium">${(item.savedRoles || []).join(', ') || 'None'}</span></p>
            </div>

            <div class="flex items-center justify-between pt-1">
                <span class="text-[11px] text-slate-500">
                    ${item.quarantinedAt ? new Date(item.quarantinedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent'}
                </span>
                <button onclick="restoreAndReleaseMember('${item.userId || item.id}', '${item.username || 'User'}')" class="px-4 py-2 bg-success/20 hover:bg-success text-success hover:text-darker border border-success/30 font-bold text-xs rounded-xl transition flex items-center space-x-1.5">
                    <i data-lucide="unlock" class="w-3.5 h-3.5"></i>
                    <span>Restore Roles & Release</span>
                </button>
            </div>
        </div>
    `).join("");

    if (window.lucide) window.lucide.createIcons();
}

// Release & Restore Member Function
window.restoreAndReleaseMember = async function (userId, username) {
    if (confirm(`Lift quarantine and restore all backed-up roles to ${username}?`)) {
        const ok = await firebaseService.releaseMember(currentGuildId, userId);
        if (ok) {
            await firebaseService.logIncident(currentGuildId, {
                type: "ROLES_RESTORED",
                severity: "INFO",
                user: username,
                action: "Quarantine lifted & all previous roles restored via Dashboard",
                confidence: "100% (Admin Action)"
            });
            showToast(`Roles restored for ${username}!`, "success");
        } else {
            showToast("Failed to release member from database.", "error");
        }
    }
};

// Render Incident Stream
function renderIncidentStream(incidents) {
    const miniList = document.getElementById("mini-incident-list");
    const fullTable = document.getElementById("incidents-table-body");

    // Mini feed
    if (miniList) {
        miniList.innerHTML = incidents.slice(0, 5).map(inc => {
            const badgeColor = inc.severity === 'CRITICAL' ? 'text-danger bg-danger/10 border-danger/30' :
                               inc.severity === 'HIGH' ? 'text-amber-400 bg-amber-400/10 border-amber-400/30' :
                               inc.severity === 'MEDIUM' ? 'text-discord bg-discord/10 border-discord/30' :
                               'text-success bg-success/10 border-success/30';
            return `
                <div class="p-3 rounded-xl bg-darker/60 border border-borderBase space-y-1.5 text-xs hover:border-discord/30 transition">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-white">${inc.type}</span>
                        <span class="px-1.5 py-0.5 text-[9px] font-bold rounded border ${badgeColor}">${inc.severity}</span>
                    </div>
                    <p class="text-slate-400 text-[11px]">${inc.action}</p>
                    <div class="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                        <span>Target: <b class="text-slate-300">${inc.user}</b></span>
                        <span>${new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                </div>
            `;
        }).join("");
    }

    // Full table view
    if (fullTable) {
        fullTable.innerHTML = incidents.map(inc => {
            const badgeColor = inc.severity === 'CRITICAL' ? 'text-danger bg-danger/10 border-danger/30' :
                               inc.severity === 'HIGH' ? 'text-amber-400 bg-amber-400/10 border-amber-400/30' :
                               inc.severity === 'MEDIUM' ? 'text-discord bg-discord/10 border-discord/30' :
                               'text-success bg-success/10 border-success/30';
            return `
                <tr class="hover:bg-darker/30 transition">
                    <td class="py-3 px-4 font-bold text-white">${inc.type}</td>
                    <td class="py-3 px-4">
                        <span class="px-2 py-0.5 text-[10px] font-bold rounded border ${badgeColor}">${inc.severity}</span>
                    </td>
                    <td class="py-3 px-4 font-mono text-slate-300">${inc.user}</td>
                    <td class="py-3 px-4 text-slate-400">${inc.action}</td>
                    <td class="py-3 px-4 text-slate-500 font-mono">${new Date(inc.timestamp).toLocaleString()}</td>
                </tr>
            `;
        }).join("");
    }

    if (window.lucide) window.lucide.createIcons();
}

// Panic Mode Emergency Trigger
function setupPanicButton() {
    const btn = document.getElementById("btn-panic-mode");
    if (btn) {
        btn.addEventListener("click", () => {
            const isCurrentlyActive = !document.getElementById("banner-panic-active")?.classList.contains("hidden");
            window.togglePanicMode(!isCurrentlyActive);
        });
    }
}

window.togglePanicMode = async function (activate) {
    const banner = document.getElementById("banner-panic-active");
    const label = document.getElementById("panic-label");
    const btn = document.getElementById("btn-panic-mode");

    if (activate) {
        if (confirm("EMERGENCY: Lock down all server channels and isolate suspicious accounts?")) {
            if (banner) banner.classList.remove("hidden");
            if (label) label.innerText = "LOCKDOWN ACTIVE";
            if (btn) btn.classList.add("panic-btn-active", "bg-danger", "text-white");
            await firebaseService.logIncident(currentGuildId, {
                type: "EMERGENCY_PANIC_MODE_ACTIVATED",
                severity: "CRITICAL",
                user: "Server Owner",
                action: "Server placed into emergency lockdown. All channels restricted.",
                confidence: "100%"
            });
            showToast("Server Lockdown Activated! All channels secured.", "error");
        }
    } else {
        if (banner) banner.classList.add("hidden");
        if (label) label.innerText = "PANIC LOCKDOWN";
        if (btn) btn.classList.remove("panic-btn-active", "bg-danger", "text-white");
        await firebaseService.logIncident(currentGuildId, {
            type: "PANIC_MODE_DEACTIVATED",
            severity: "INFO",
            user: "Server Owner",
            action: "Lockdown lifted. Normal permissions restored.",
            confidence: "100%"
        });
        showToast("Lockdown lifted. Server permissions restored.", "success");
    }
};

// Modal Handlers
window.promptManualQuarantine = function () {
    document.getElementById("modal-manual-quarantine")?.classList.remove("hidden");
};

window.closeManualQuarantineModal = function () {
    document.getElementById("modal-manual-quarantine")?.classList.add("hidden");
};

window.submitManualQuarantine = async function () {
    const uid = document.getElementById("input-q-userid")?.value.trim();
    const reason = document.getElementById("input-q-reason")?.value.trim() || "Manual quarantine via web dashboard";

    if (!uid) {
        alert("Please enter a valid Discord User ID.");
        return;
    }

    const newRecord = {
        userId: uid,
        username: `User_${uid.slice(-4)}`,
        avatar: "https://cdn.discordapp.com/embed/avatars/3.png",
        quarantinedAt: new Date().toISOString(),
        reason: reason,
        savedRoles: ["Member"],
        quarantinedBy: "Server Owner (Web Dashboard)"
    };

    if (!firebaseService.isLive) {
        const local = localStorage.getItem(`karuppu_quarantine_${currentGuildId}`);
        const list = local ? JSON.parse(local) : [...MOCK_DATA.quarantine];
        list.unshift(newRecord);
        localStorage.setItem(`karuppu_quarantine_${currentGuildId}`, JSON.stringify(list));
        renderQuarantineCards(list);
    } else {
        // Live firestore
        import("https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js").then(async ({ doc, setDoc }) => {
            const ref = doc(firebaseService.db, `guilds/${currentGuildId}/quarantine`, uid);
            await setDoc(ref, newRecord);
        });
    }

    await firebaseService.logIncident(currentGuildId, {
        type: "MANUAL_QUARANTINE_ISSUED",
        severity: "HIGH",
        user: uid,
        action: `Isolated user & revoked channel access (${reason})`,
        confidence: "100% (Owner Action)"
    });

    closeManualQuarantineModal();
    showToast(`User ${uid} placed into Quarantine!`, "success");
};

// Firebase Config Modal Controls
const btnOpenFirebase = document.getElementById("btn-open-firebase");
const btnDbStatus = document.getElementById("btn-db-status");

if (btnOpenFirebase) btnOpenFirebase.addEventListener("click", openFirebaseModal);
if (btnDbStatus) btnDbStatus.addEventListener("click", openFirebaseModal);

function openFirebaseModal() {
    const modal = document.getElementById("modal-firebase");
    const input = document.getElementById("firebase-json-input");
    const saved = firebaseService.getConfig();
    if (input && saved) {
        input.value = JSON.stringify(saved, null, 2);
    }
    if (modal) modal.classList.remove("hidden");
}

window.closeFirebaseModal = function () {
    document.getElementById("modal-firebase")?.classList.add("hidden");
};

window.saveFirebaseCredentials = function () {
    const input = document.getElementById("firebase-json-input")?.value.trim();
    if (!input) {
        alert("Please paste your Firebase configuration JSON.");
        return;
    }
    try {
        const config = JSON.parse(input);
        const res = firebaseService.connect(config);
        if (res.success) {
            updateDbStatusPill();
            closeFirebaseModal();
            showToast("Connected live to Firebase Firestore!", "success");
            setupRealtimeSubscriptions();
        } else {
            alert(`Connection error: ${res.error}`);
        }
    } catch (e) {
        alert("Invalid JSON format. Please paste the exact object from the Firebase console.");
    }
};

window.disconnectFirebase = function () {
    firebaseService.disconnect();
    updateDbStatusPill();
    closeFirebaseModal();
    showToast("Switched to Local Demo Mode.", "info");
    setupRealtimeSubscriptions();
};

function updateDbStatusPill() {
    const pill = document.getElementById("btn-db-status");
    const label = document.getElementById("db-status-label");
    if (!pill || !label) return;

    if (firebaseService.isLive) {
        pill.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-medium transition bg-success/10 border-success/30 text-success hover:bg-success/20";
        label.innerText = "Firebase Live (Real-Time)";
    } else {
        pill.className = "flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-medium transition bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20";
        label.innerText = "Demo Mode (Connect Firebase)";
    }
}

// Clear Logs
window.clearIncidentLogs = async function () {
    if (confirm("Clear local incident history?")) {
        localStorage.removeItem(`karuppu_incidents_${currentGuildId}`);
        renderIncidentStream([]);
        showToast("Incident log history cleared.", "info");
    }
};

// Toast notification helper
function showToast(message, type = "info") {
    const toast = document.createElement("div");
    const bg = type === "success" ? "bg-success text-darker font-bold" :
               type === "error" ? "bg-danger text-white font-bold" :
               "bg-discord text-white font-bold";

    toast.className = `fixed bottom-6 right-6 z-50 px-5 py-3 rounded-xl shadow-2xl ${bg} text-xs transition-all duration-300 flex items-center space-x-2 transform translate-y-2 opacity-0`;
    toast.innerHTML = `<span>${message}</span>`;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.remove("translate-y-2", "opacity-0");
    }, 10);

    setTimeout(() => {
        toast.classList.add("translate-y-2", "opacity-0");
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

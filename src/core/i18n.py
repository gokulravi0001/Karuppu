"""Internationalization and localization manager for multi-server language support."""
from typing import Dict, Any, Optional

# Multi-language string catalog
TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        "bot_title": "Karuppu Security Bot",
        "maintenance_active": "🛠️ **System Maintenance in Progress**\nKaruppu is currently undergoing scheduled maintenance or system optimization. Operational commands are temporarily paused. Essential internal monitoring remains active.",
        "maintenance_developer_notice": "ℹ️ Developer bypass active. System running in maintenance mode.",
        "blacklisted_user": "⛔ You have been blacklisted from using Karuppu Security bot.",
        "blacklisted_guild": "⛔ This server has been blacklisted from Karuppu Security operations.",
        "cooldown_notice": "⏳ Slow down! You can use this command again in `{remaining:.1f}` seconds.",
        "module_disabled": "⚠️ The module `{module}` is currently disabled on this server.",
        "emergency_module_disabled": "🚨 The `{module}` system has been temporarily disabled globally by developers.",
        "unauthorized_admin": "❌ You must have Administrator or Manage Server permissions to perform this action.",
        "unauthorized_developer": "⛔ Restricted: This action requires Bot Developer privileges.",
        "sync_success": "✅ Log channels successfully synced without creating new channels.",
        "quarantine_success": "🛡️ User `{user}` placed into quarantine. Threat isolated.",
        "restore_success": "✅ Quarantine lifted for user `{user}`. Original roles restored."
    },
    "es": {
        "bot_title": "Bot de Seguridad Karuppu",
        "maintenance_active": "🛠️ **Mantenimiento del Sistema en Progreso**\nKaruppu se encuentra actualmente en mantenimiento. Los comandos operativos están temporalmente en pausa.",
        "blacklisted_user": "⛔ Has sido bloqueado para usar el bot Karuppu.",
        "blacklisted_guild": "⛔ Este servidor ha sido bloqueado para las operaciones de Karuppu.",
        "cooldown_notice": "⏳ ¡Espera! Puedes usar este comando de nuevo en `{remaining:.1f}` segundos.",
        "module_disabled": "⚠️ El módulo `{module}` está desactivado en este servidor.",
        "unauthorized_admin": "❌ Debes tener permisos de Administrador para realizar esta acción.",
        "unauthorized_developer": "⛔ Restringido: Requiere privilegios de Desarrollador."
    },
    "ta": {
        "bot_title": "கருப்பு பாதுகாப்பு பாட்",
        "maintenance_active": "🛠️ **பராமரிப்பு பணி நடைபெறுகிறது**\nகருப்பு தற்போது பராமரிப்பில் உள்ளது. கட்டளைகள் தற்காலிகமாக நிறுத்தப்பட்டுள்ளன.",
        "blacklisted_user": "⛔ நீங்கள் கருப்பு பாட்டை பயன்படுத்த தடை செய்யப்பட்டுள்ளீர்கள்.",
        "blacklisted_guild": "⛔ இந்த சேவையகம் தடை செய்யப்பட்டுள்ளது.",
        "cooldown_notice": "⏳ சிறிது நேரம் காத்திருங்கள்! `{remaining:.1f}` வினாடிகளில் மீண்டும் இயக்கலாம்.",
        "module_disabled": "⚠️ `{module}` தொகுதி இந்த சேவையகத்தில் முடக்கப்பட்டுள்ளது."
    }
}

class I18nManager:
    """Manages string translations and per-server language resolution."""
    def __init__(self, default_locale: str = "en"):
        self.default_locale = default_locale
        self.translations = TRANSLATIONS

    def get(self, key: str, locale: Optional[str] = None, **kwargs) -> str:
        """Retrieves and formats a localized string key."""
        loc = (locale or self.default_locale).lower()
        cat = self.translations.get(loc, self.translations.get(self.default_locale, {}))
        template = cat.get(key)

        if not template:
            # Fallback to English
            template = self.translations.get(self.default_locale, {}).get(key, key)

        if kwargs:
            try:
                return template.format(**kwargs)
            except Exception:
                return template
        return template

i18n = I18nManager()

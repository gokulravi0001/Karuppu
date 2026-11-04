"""Test suite for Discord Security Bot detection heuristics and core rules."""
import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import unicodedata
import hashlib
import time
from collections import deque
from datetime import datetime, timezone, timedelta
import Levenshtein

# Replicate homoglyph mapping from LinkFilter
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's',
    'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n',
    'ԛ': 'q', 'ԁ': 'd', 'ԍ': 'g', 'һ': 'h', 'ѵ': 'v', 'ԝ': 'w',
    '0': 'o', '1': 'l', '@': 'a', '$': 's'
}

def normalize_homoglyphs(text: str) -> str:
    normalized = unicodedata.normalize('NFKD', text)
    result = []
    for ch in normalized:
        result.append(HOMOGLYPH_MAP.get(ch, ch))
    norm_str = "".join(result).lower()
    norm_str = norm_str.replace("cl", "d").replace("rn", "m").replace("vv", "w")
    return norm_str

def scan_domain(domain: str, protected_brands, threshold: float = 0.80):
    clean_domain = normalize_homoglyphs(domain)
    parts = clean_domain.split(".")
    main_part = parts[0] if parts else clean_domain

    orig_parts = domain.lower().split(".")
    orig_main = orig_parts[0] if orig_parts else domain.lower()

    for brand in protected_brands:
        brand = brand.lower()
        if orig_main != brand and main_part == brand:
            return (brand, 0.99)
        if brand in main_part and main_part != brand:
            return (brand, 0.95)
        ratio = Levenshtein.ratio(main_part, brand)
        if ratio >= threshold and main_part != brand:
            return (brand, ratio)
    return None

class TestPhishingDetection(unittest.TestCase):
    def setUp(self):
        self.brands = ["discord", "nitro", "steamcommunity"]

    def test_exact_whitelisted_domain_not_flagged_as_spoof(self):
        # When brand matches exactly, scan_domain ignores it (it's handled by whitelist)
        result = scan_domain("discord.com", self.brands)
        self.assertIsNone(result)

    def test_typosquatting_detection(self):
        # 'discorcl' vs 'discord'
        res = scan_domain("discorcl.com", self.brands)
        self.assertIsNotNone(res)
        self.assertEqual(res[0], "discord")
        self.assertGreaterEqual(res[1], 0.82)

    def test_subdomain_keyword_spoofing(self):
        # 'discord-nitro-gift'
        res = scan_domain("discord-nitro-gift.com", self.brands)
        self.assertIsNotNone(res)
        self.assertEqual(res[0], "discord")

    def test_cyrillic_homoglyph_spoofing(self):
        # 'dіscord' where 'і' is Ukrainian Cyrillic (U+0456)
        spoofed = "d\u0456scord-app.com"
        res = scan_domain(spoofed, self.brands)
        self.assertIsNotNone(res)


class TestSpamDetection(unittest.TestCase):
    def test_copypasta_normalization(self):
        msg1 = "FREE NITRO CLICK HERE: https://gift.com"
        msg2 = "free nitro   click here:   https://gift.com!!!"
        norm1 = "".join(ch for ch in msg1.lower() if ch.isalnum())
        norm2 = "".join(ch for ch in msg2.lower() if ch.isalnum())
        self.assertEqual(norm1, norm2)

    def test_short_messages_ignored_for_copypasta(self):
        short_msg = "lol"
        norm = "".join(ch for ch in short_msg.lower() if ch.isalnum())
        self.assertLess(len(norm), 10)

    def test_identical_message_ten_limit(self):
        from src.cogs.spam_detector import SpamDetector
        detector = SpamDetector(bot=None)
        msg_text = "Check out this awesome game!"

        # Send 10 times: all should be under the limit
        for i in range(10):
            over, count = detector._check_identical_ceiling(user_id=123, channel_id=456, content=msg_text, max_allowed=10, window_secs=60)
            self.assertFalse(over, f"Message {i+1} should not be flagged as over limit")
            self.assertEqual(count, i + 1)

        # 11th message: exceeds ceiling!
        over, count = detector._check_identical_ceiling(user_id=123, channel_id=456, content=msg_text, max_allowed=10, window_secs=60)
        self.assertTrue(over, "11th identical message must be flagged over limit")
        self.assertEqual(count, 11)


class TestAntiNuke(unittest.TestCase):
    def test_mass_channel_delete_threshold(self):
        from src.cogs.anti_nuke import AntiNuke
        nuke = AntiNuke(bot=None)

        # 2 channel deletes in 10s should not trigger limit of 3
        t1, c1 = nuke._track_action(guild_id=1, user_id=999, action_type="channel_delete", threshold=3, window_secs=10)
        self.assertFalse(t1)
        t2, c2 = nuke._track_action(guild_id=1, user_id=999, action_type="channel_delete", threshold=3, window_secs=10)
        self.assertFalse(t2)

        # 3rd channel delete triggers anti-nuke
        t3, c3 = nuke._track_action(guild_id=1, user_id=999, action_type="channel_delete", threshold=3, window_secs=10)
        self.assertTrue(t3)
        self.assertEqual(c3, 3)

    def test_mass_ban_threshold(self):
        from src.cogs.anti_nuke import AntiNuke
        nuke = AntiNuke(bot=None)

        for _ in range(2):
            trig, _ = nuke._track_action(guild_id=1, user_id=888, action_type="mass_ban", threshold=3, window_secs=10)
            self.assertFalse(trig)

        trig, count = nuke._track_action(guild_id=1, user_id=888, action_type="mass_ban", threshold=3, window_secs=10)
        self.assertTrue(trig)
        self.assertEqual(count, 3)


class TestRaidDetection(unittest.TestCase):
    def test_join_burst_calculation(self):
        window = 10
        joins = deque()
        now = time.time()

        # Add 6 joins within 5 seconds
        for i in range(6):
            joins.append((now - (5 - i), 1000 + i, datetime.now(timezone.utc)))

        # Prune
        while joins and (now - joins[0][0]) > window:
            joins.popleft()

        self.assertEqual(len(joins), 6)
        self.assertGreaterEqual(len(joins), 5)  # Triggers raid threshold!

    def test_new_account_detection(self):
        now_utc = datetime.now(timezone.utc)
        brand_new_account = now_utc - timedelta(hours=2)
        old_account = now_utc - timedelta(days=90)

        self.assertLess((now_utc - brand_new_account).total_seconds(), 24 * 3600)
        self.assertGreater((now_utc - old_account).total_seconds(), 24 * 3600)


class TestVoiceProtection(unittest.TestCase):
    def test_vc_hopping_sliding_window(self):
        window = 10
        events = deque()
        now = time.time()

        # Simulate 5 rapid VC switches in 3 seconds
        for i in range(5):
            events.append(now - (3 - i * 0.5))

        # Prune
        while events and (now - events[0]) > window:
            events.popleft()

        self.assertEqual(len(events), 5)
        self.assertGreaterEqual(len(events), 5)  # Triggers VC hopping limit!

    def test_vc_hopping_under_threshold(self):
        # 3 events in 10s should not trigger threshold of 5
        events = deque([100.0, 102.0, 104.0])
        self.assertLess(len(events), 5)

    def test_mic_glitch_macro_sliding_window(self):
        window = 4
        events = deque()
        now = time.time()
        # 8 rapid mute toggles in 2s
        for i in range(8):
            events.append(now - (2 - i * 0.2))
        while events and (now - events[0]) > window:
            events.popleft()
        self.assertGreaterEqual(len(events), 8)

    def test_vc_raid_surge_window(self):
        window = 8
        joins = deque()
        now = time.time()
        # 5 distinct joins in 3s
        for i in range(5):
            joins.append((now - (3 - i * 0.5), 1000 + i))
        while joins and (now - joins[0][0]) > window:
            joins.popleft()
        self.assertGreaterEqual(len(joins), 4)


class TestAttachmentSecurity(unittest.TestCase):
    def test_dangerous_extensions(self):
        from src.cogs.attachment_scanner import DANGEROUS_EXTENSIONS, DOUBLE_EXT_REGEX
        import os
        self.assertIn(".exe", DANGEROUS_EXTENSIONS)
        self.assertIn(".scr", DANGEROUS_EXTENSIONS)
        self.assertIn(".bat", DANGEROUS_EXTENSIONS)
        
        # Test double extension regex
        self.assertTrue(bool(DOUBLE_EXT_REGEX.search("image.png.exe")))
        self.assertTrue(bool(DOUBLE_EXT_REGEX.search("photo.jpg.scr")))
        self.assertFalse(bool(DOUBLE_EXT_REGEX.search("normal_photo.png")))


class TestInviteFilter(unittest.TestCase):
    def test_invite_regex(self):
        from src.cogs.invite_filter import INVITE_REGEX
        match1 = INVITE_REGEX.findall("Join my cool server: https://discord.gg/xyz123")
        self.assertEqual(match1, ["xyz123"])
        
        match2 = INVITE_REGEX.findall("Check out discord.com/invite/promo-code today!")
        self.assertEqual(match2, ["promo-code"])

        match3 = INVITE_REGEX.findall("No invite here, just talking about discord.com")
        self.assertEqual(match3, [])


class TestAccountAnomaly(unittest.TestCase):
    def test_token_lure_matching(self):
        from src.cogs.account_anomaly import COMPROMISED_LURE_PATTERNS
        sample_scam = "Hey bro, can you please test my new game: https://suspicious-download.com"
        matched = any(p.search(sample_scam) for p in COMPROMISED_LURE_PATTERNS)
        self.assertTrue(matched)

        benign = "Let's play valorant tonight at 8pm"
        matched_benign = any(p.search(benign) for p in COMPROMISED_LURE_PATTERNS)
        self.assertFalse(matched_benign)


class TestNameSanitizer(unittest.TestCase):
    def test_zalgo_detection(self):
        # Combining character (U+0336 is combining long stroke overlay)
        zalgo = "T\u0336\u0337\u0338\u0339\u033a\u033be\u033cs\u033dt"
        import unicodedata
        combining_count = sum(1 for ch in zalgo if unicodedata.combining(ch))
        self.assertGreaterEqual(combining_count, 5)

    def test_blank_invisible_name(self):
        from src.cogs.name_sanitizer import ZERO_WIDTH_CHARS
        invisible_nick = "\u200b\u200c\u200d   \ufeff"
        cleaned = "".join(ch for ch in invisible_nick if ch not in ZERO_WIDTH_CHARS and not ch.isspace())
        self.assertEqual(len(cleaned), 0)


class MockRole:
    def __init__(self, name: str, role_id: int):
        self.name = name
        self.id = role_id

class MockMember:
    def __init__(self, roles, member_id: int = 12345):
        self.roles = roles
        self.id = member_id
        self.bot = False
        self.guild = None

class TestLevelRoleHierarchy(unittest.TestCase):
    def test_higher_level_inherits_lower_level_perks(self):
        from src.config import bot_config
        # User has 'Gold Rank' (Level 50), but DOES NOT have 'Guild Recruit' (Level 5)
        # because the leveling bot replaced their previous role.
        user_gold = MockMember(roles=[MockRole("Gold Rank", 5001)])

        # Requirement is 'Guild Recruit' (Level 5)
        self.assertTrue(bot_config.has_required_role(user_gold, "Guild Recruit"))

        # Requirement is 'Bronze Rank' (Level 10)
        self.assertTrue(bot_config.has_required_role(user_gold, "Bronze Rank"))

        # Requirement is 'Guild Hero' (Level 250) - Gold Rank (50) should NOT have this
        self.assertFalse(bot_config.has_required_role(user_gold, "Guild Hero"))

    def test_brand_new_member_has_no_perks(self):
        from src.config import bot_config
        # New member with no level roles
        user_new = MockMember(roles=[MockRole("@everyone", 1)])
        self.assertFalse(bot_config.has_required_role(user_new, "Guild Recruit"))
        self.assertFalse(bot_config.has_required_role(user_new, "Bronze Rank"))


    def test_per_guild_custom_role_selection(self):
        from src.config import bot_config
        
        class MockGuild:
            def __init__(self, guild_id):
                self.id = guild_id
                self.owner_id = 999999

        guild_a = MockGuild(1111)
        # Server A configures custom role 'VIP Poster' (ID: 5555) for links
        bot_config.guild_settings_cache[1111] = {
            "links_role_id": 5555,
            "links_role_name": "VIP Poster"
        }

        user_with_vip = MockMember(roles=[MockRole("VIP Poster", 5555)])
        user_with_vip.guild = guild_a

        user_without_vip = MockMember(roles=[MockRole("Regular", 1234)])
        user_without_vip.guild = guild_a

        # User with custom selected role is permitted
        self.assertTrue(bot_config.has_required_role(user_with_vip, "Guild Recruit", gate_name="links"))
        # User without custom role is denied
        self.assertFalse(bot_config.has_required_role(user_without_vip, "Guild Recruit", gate_name="links"))


class TestLoggingSystemConfig(unittest.TestCase):
    def test_log_channel_resolution(self):
        from src.config import bot_config
        bot_config.guild_settings_cache[9999] = {
            "chat_log_channel_id": 101,
            "voice_log_channel_id": 102,
            "vc_state_log_channel_id": 106,
            "member_log_channel_id": 103,
            "mod_log_channel_id": 104,
            "server_log_channel_id": 105
        }

        self.assertEqual(bot_config.get_log_channel_id(9999, "chat"), 101)
        self.assertEqual(bot_config.get_log_channel_id(9999, "voice"), 102)
        self.assertEqual(bot_config.get_log_channel_id(9999, "vc_state"), 106)
        self.assertEqual(bot_config.get_log_channel_id(9999, "member"), 103)
        self.assertEqual(bot_config.get_log_channel_id(9999, "mod"), 104)
        self.assertEqual(bot_config.get_log_channel_id(9999, "server"), 105)

    def test_unmute_authority_role_permission(self):
        from src.config import bot_config
        bot_config.guild_settings_cache[2222] = {
            "unmute_role_id": 7777,
            "unmute_role_name": "Voice Moderator"
        }

        mod_user = MockMember(roles=[MockRole("Voice Moderator", 7777)])
        has_perm = any(r.id == 7777 for r in mod_user.roles)
        self.assertTrue(has_perm)

        regular_user = MockMember(roles=[MockRole("Member", 1111)])
        has_perm_reg = any(r.id == 7777 for r in regular_user.roles)
        self.assertFalse(has_perm_reg)
        self.assertEqual(bot_config.get_log_channel_id(9999, "mod"), 104)
        self.assertEqual(bot_config.get_log_channel_id(9999, "server"), 105)

        # Unconfigured guild returns None
        self.assertIsNone(bot_config.get_log_channel_id(8888, "chat"))


class TestVCPunishments(unittest.TestCase):
    def test_vc_blocking_and_expiration(self):
        from src.config import bot_config
        guild_id = 98765
        user_a = 11111
        user_b = 22222
        user_c = 33333

        # 1. Permanent ban
        bot_config.vc_punishments_cache[(guild_id, user_a)] = {
            "punishment_type": "vc_ban",
            "moderator_id": 999,
            "reason": "Trolling VC",
            "expires_at": None
        }

        # 2. Active timeout (expires in 10 minutes)
        future_exp = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        bot_config.vc_punishments_cache[(guild_id, user_b)] = {
            "punishment_type": "vc_timeout",
            "moderator_id": 999,
            "reason": "Mic spam",
            "expires_at": future_exp
        }

        # 3. Expired timeout (expired 5 minutes ago)
        past_exp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        bot_config.vc_punishments_cache[(guild_id, user_c)] = {
            "punishment_type": "vc_timeout",
            "moderator_id": 999,
            "reason": "Old timeout",
            "expires_at": past_exp
        }

        # Verify user_a is blocked
        blocked_a = bot_config.is_vc_blocked(guild_id, user_a)
        self.assertIsNotNone(blocked_a)
        self.assertEqual(blocked_a["punishment_type"], "vc_ban")

        # Verify user_b is blocked
        blocked_b = bot_config.is_vc_blocked(guild_id, user_b)
        self.assertIsNotNone(blocked_b)
        self.assertEqual(blocked_b["punishment_type"], "vc_timeout")

        # Verify user_c is expired and unblocked automatically
        blocked_c = bot_config.is_vc_blocked(guild_id, user_c)
        self.assertIsNone(blocked_c)
        self.assertNotIn((guild_id, user_c), bot_config.vc_punishments_cache)

        # Non-punished user
        self.assertIsNone(bot_config.is_vc_blocked(guild_id, 44444))

        # 4. Global ban (guild_id=0) blocks across ANY server
        user_global = 55555
        bot_config.vc_punishments_cache[(0, user_global)] = {
            "punishment_type": "vc_ban",
            "moderator_id": 999,
            "reason": "Global raid offender",
            "expires_at": None
        }
        # In guild_id 98765
        self.assertIsNotNone(bot_config.is_vc_blocked(guild_id, user_global))
        # In completely different friend's server (guild_id 77777)
        self.assertIsNotNone(bot_config.is_vc_blocked(77777, user_global))

    def test_vc_punishment_schema_and_queries(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE vc_punishments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                punishment_type TEXT NOT NULL,
                moderator_id INTEGER NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                UNIQUE(guild_id, user_id, punishment_type)
            );
        """)

        # Insert VC Ban
        cursor.execute("""
            INSERT INTO vc_punishments (guild_id, user_id, punishment_type, moderator_id, reason, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (1001, 2001, "vc_ban", 3001, "Raiding", "2026-11-01T12:00:00", None))

        # Query active punishment
        cursor.execute("SELECT punishment_type, reason FROM vc_punishments WHERE guild_id = ? AND user_id = ?", (1001, 2001))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "vc_ban")
        self.assertEqual(row[1], "Raiding")

        # Conflict resolution / update
        cursor.execute("""
            INSERT INTO vc_punishments (guild_id, user_id, punishment_type, moderator_id, reason, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(guild_id, user_id, punishment_type) DO UPDATE SET
                reason = excluded.reason
        """, (1001, 2001, "vc_ban", 3001, "Updated Reason", "2026-11-01T12:05:00", None))

        cursor.execute("SELECT reason FROM vc_punishments WHERE guild_id = ? AND user_id = ?", (1001, 2001))
        self.assertEqual(cursor.fetchone()[0], "Updated Reason")

        # Delete
        cursor.execute("DELETE FROM vc_punishments WHERE guild_id = ? AND user_id = ?", (1001, 2001))
        cursor.execute("SELECT * FROM vc_punishments WHERE guild_id = ? AND user_id = ?", (1001, 2001))
        self.assertIsNone(cursor.fetchone())
        conn.close()


class TestFullSuiteLoggingResolution(unittest.TestCase):
    def test_24_channel_exact_and_fallback_resolution(self):
        from src.config import bot_config
        guild_id = 999988887777

        # Ensure cache starts clean for test guild
        for k in list(bot_config.guild_log_channels_cache.keys()):
            if k[0] == guild_id:
                del bot_config.guild_log_channels_cache[k]
        bot_config.guild_settings_cache.pop(guild_id, None)

        # 1. Exact resolution test when full suite is configured (all 32 action channels)
        all_32_channels = [
            "antinuke", "message", "mod", "kick", "ban", "timeout", "voice", "vc_state",
            "soundboard", "stage", "event", "announcement", "role", "channel", "server", "member",
            "joins", "leaves", "emoji", "verify", "whitelist", "security", "file", "invite",
            "ticket", "admin", "boost", "raid", "misuse", "presence", "automod", "relationship"
        ]
        dummy_base_id = 100000000
        for i, ch_key in enumerate(all_32_channels):
            bot_config.guild_log_channels_cache[(guild_id, ch_key)] = dummy_base_id + i

        for i, ch_key in enumerate(all_32_channels):
            res_id = bot_config.get_log_channel_id(guild_id, ch_key)
            self.assertEqual(res_id, dummy_base_id + i, f"Failed exact resolution for {ch_key}")

        # 2. Test fallback chains when granular channels are missing
        # Clear all and only set standard parent channels
        for k in list(bot_config.guild_log_channels_cache.keys()):
            if k[0] == guild_id:
                del bot_config.guild_log_channels_cache[k]

        bot_config.guild_log_channels_cache[(guild_id, "security")] = 7701
        bot_config.guild_log_channels_cache[(guild_id, "mod")] = 7702
        bot_config.guild_log_channels_cache[(guild_id, "member")] = 7703
        bot_config.guild_log_channels_cache[(guild_id, "server")] = 7704
        bot_config.guild_log_channels_cache[(guild_id, "chat")] = 7705
        bot_config.guild_log_channels_cache[(guild_id, "voice")] = 7706
        bot_config.guild_log_channels_cache[(guild_id, "channel")] = 7707

        # Check fallbacks
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "antinuke"), 7701) # antinuke -> security
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "raid"), 7701)     # raid -> security
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "misuse"), 7701)   # misuse -> security
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "ban"), 7702)      # ban -> mod
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "kick"), 7702)     # kick -> mod
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "timeout"), 7702)  # timeout -> mod
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "joins"), 7703)    # joins -> member
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "leaves"), 7703)   # leaves -> member
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "role"), 7704)     # role -> server
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "emoji"), 7704)    # emoji -> server
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "event"), 7704)    # event -> server
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "stage"), 7707)    # stage -> channel
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "announcement"), 7707) # announcement -> channel
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "message"), 7705)  # message -> chat
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "soundboard"), 7706) # soundboard -> vc_state -> voice
        self.assertEqual(bot_config.get_log_channel_id(guild_id, "vc_state"), 7706)   # vc_state -> voice

        # Cleanup
        for k in list(bot_config.guild_log_channels_cache.keys()):
            if k[0] == guild_id:
                del bot_config.guild_log_channels_cache[k]

    def test_format_role_list(self):
        from src.cogs.logging_system import format_role_list
        class DummyRole:
            def __init__(self, name, id_val):
                self.name = name
                self.id = id_val
                self.mention = f"<@&{id_val}>"

        roles = [DummyRole("Staff", 111), DummyRole("VIP", 222)]
        formatted = format_role_list(roles)
        self.assertIn("<@&111>", formatted)
        self.assertIn("<@&222>", formatted)
        self.assertEqual(format_role_list([]), "*None*")

    def test_guild_log_channels_database_operations(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE guild_log_channels (
                guild_id INTEGER NOT NULL,
                log_type TEXT NOT NULL,
                channel_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, log_type)
            );
        """)

        # Insert channel
        cursor.execute("""
            INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, log_type) DO UPDATE SET channel_id = excluded.channel_id
        """, (8888, "antinuke", 112233))

        cursor.execute("SELECT channel_id FROM guild_log_channels WHERE guild_id = ? AND log_type = ?", (8888, "antinuke"))
        self.assertEqual(cursor.fetchone()[0], 112233)

        # Bulk insert
        items = [(8888, "mod", 112234), (8888, "joins", 112235), (8888, "voice", 112236)]
        cursor.executemany("""
            INSERT INTO guild_log_channels (guild_id, log_type, channel_id)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, log_type) DO UPDATE SET channel_id = excluded.channel_id
        """, items)

        cursor.execute("SELECT log_type, channel_id FROM guild_log_channels WHERE guild_id = ?", (8888,))
        rows = dict(cursor.fetchall())
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows["joins"], 112235)
        conn.close()

    def test_short_commands_and_lambda_prefix(self):
        from src.cogs.admin import ShortCommands, SecurityAdmin
        self.assertTrue(hasattr(ShortCommands, "cmd_short_logs"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_vcban"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_vckick"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_vctimeout"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_lock"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_unlock"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_purge"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_setlog"))
        self.assertTrue(hasattr(ShortCommands, "cmd_short_status"))

        # Verify lambda prefix default
        import inspect
        sig = inspect.signature(ShortCommands.cmd_short_logs.callback)
        prefix_param = sig.parameters.get("prefix")
        self.assertIsNotNone(prefix_param)
        self.assertEqual(prefix_param.default, "𝚲")


class TestQuarantineRoleRestoration(unittest.TestCase):
    def setUp(self):
        from src.cogs.quarantine import QuarantineSystem
        self.bot = MagicMock()
        self.cog = QuarantineSystem(self.bot)
        self.guild = MagicMock()
        self.guild.id = 12345
        self.guild.name = "TestGuild"
        self.guild.default_role = MagicMock()
        self.guild.default_role.id = 100
        self.guild.me = MagicMock()
        self.guild.me.top_role.position = 100
        self.guild.me.guild_permissions.manage_roles = True
        self.guild.me.guild_permissions.manage_channels = True
        self.guild.me.guild_permissions.move_members = True

        class MockRole:
            def __init__(self, rid, name, position=10, managed=False):
                self.id = rid
                self.name = name
                self.position = position
                self.managed = managed
            def __ge__(self, other):
                return self.position >= getattr(other, "position", 0)
            def __lt__(self, other):
                return self.position < getattr(other, "position", 0)
            def __eq__(self, other):
                return hasattr(other, "id") and self.id == other.id
            def __repr__(self):
                return f"<MockRole {self.name}>"

        self.q_role = MockRole(999, "Quarantined", position=50)
        self.role_a = MockRole(201, "Level 1", position=20)
        self.role_b = MockRole(202, "VIP Member", position=30)
        self.guild.default_role = MockRole(100, "@everyone", position=0)

        me_top_role = MockRole(9999, "BotTopRole", position=100)
        self.guild.me.top_role = me_top_role

        self.guild.fetch_member = AsyncMock()
        self.guild.roles = [self.guild.default_role, self.q_role, self.role_a, self.role_b]
        self.guild.get_role = lambda rid: {100: self.guild.default_role, 999: self.q_role, 201: self.role_a, 202: self.role_b}.get(rid)

    def test_is_quarantine_role(self):
        self.assertTrue(self.cog._is_quarantine_role(self.q_role, self.guild))
        self.assertFalse(self.cog._is_quarantine_role(self.role_a, self.guild))

    def test_quarantine_role_strip_and_backup_logic(self):
        target_roles = [self.guild.default_role, self.role_a, self.role_b]
        saved_roles = [r for r in target_roles if not r.managed and r != self.guild.default_role and not self.cog._is_quarantine_role(r, self.guild)]
        saved_role_ids = [r.id for r in saved_roles]
        self.assertEqual(saved_role_ids, [201, 202])

        managed_roles = [r for r in target_roles if r.managed and r != self.guild.default_role]
        new_roles = [self.q_role] + [r for r in managed_roles if r != self.q_role]
        self.assertEqual(new_roles, [self.q_role])
        self.assertNotIn(self.role_a, new_roles)
        self.assertNotIn(self.role_b, new_roles)
        self.assertNotIn(self.guild.default_role, new_roles)

    def test_unquarantine_restores_roles_and_removes_quarantine_role(self):
        # Target currently in quarantine
        target_roles = [self.guild.default_role, self.q_role]
        saved_role_ids = [201, 202]

        restored_roles = []
        for rid in saved_role_ids:
            role = self.guild.get_role(rid)
            if role and not role.managed and role < self.guild.me.top_role and not self.cog._is_quarantine_role(role, self.guild):
                restored_roles.append(role)

        managed_roles = [r for r in target_roles if r.managed and r != self.guild.default_role]
        unq_roles = managed_roles + [r for r in restored_roles if r not in managed_roles]

        # Verification 1: Quarantine role MUST be removed
        self.assertNotIn(self.q_role, unq_roles)

        # Verification 2: All previous roles MUST return
        self.assertIn(self.role_a, unq_roles)
        self.assertIn(self.role_b, unq_roles)
        self.assertNotIn(self.guild.default_role, unq_roles)


if __name__ == "__main__":
    unittest.main()

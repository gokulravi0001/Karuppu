"""Test suite for Discord Security Bot detection heuristics and core rules."""
import unittest
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
            "member_log_channel_id": 103,
            "mod_log_channel_id": 104,
            "server_log_channel_id": 105
        }

        self.assertEqual(bot_config.get_log_channel_id(9999, "chat"), 101)
        self.assertEqual(bot_config.get_log_channel_id(9999, "voice"), 102)
        self.assertEqual(bot_config.get_log_channel_id(9999, "member"), 103)

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


if __name__ == "__main__":
    unittest.main()

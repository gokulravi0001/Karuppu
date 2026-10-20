"""Unit tests for Web Dashboard, OAuth2 AuthManager, and HTML template rendering."""
import unittest
import json
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp import web
from src.dashboard.auth import AuthManager
from src.dashboard.views import jinja_env, setup_dashboard_routes

class DummyBot:
    def __init__(self):
        self.guilds = []
        self.latency = 0.042
        self.user = None
    def is_ready(self):
        return True
    def get_guild(self, guild_id):
        return None
    def get_cog(self, name):
        return None

class TestAuthManager(unittest.TestCase):
    def setUp(self):
        self.auth = AuthManager()
        self.auth.client_id = "123456789"
        self.auth.client_secret = "secret_xyz"
        self.auth.dashboard_url = "http://localhost:8080"
        self.auth.session_secret = b"test_secret_key_32_bytes_long_!"

    def test_get_oauth_url(self):
        url = self.auth.get_oauth_url()
        self.assertIn("https://discord.com/oauth2/authorize", url)
        self.assertIn("client_id=123456789", url)
        self.assertIn("scope=identify+guilds", url)
        self.assertIn("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback", url)

    def test_sign_and_decode_session(self):
        data = {"user": {"id": "111", "username": "AdminGuy"}, "access_token": "token_abc"}
        signed = self.auth.sign_session(data)
        decoded = self.auth.decode_session(signed)
        self.assertEqual(decoded["user"]["username"], "AdminGuy")
        self.assertEqual(decoded["access_token"], "token_abc")

    def test_tampered_session_rejected(self):
        data = {"user": {"id": "111", "username": "AdminGuy"}}
        signed = self.auth.sign_session(data)
        tampered = signed[:-4] + "AAAA"
        self.assertIsNone(self.auth.decode_session(tampered))

class TestTemplateRendering(unittest.TestCase):
    def test_templates_compile_and_render(self):
        dummy_context = {
            "title": "Test Title",
            "user": {"id": "12345", "username": "TestUser", "avatar": "abcdef"},
            "client_id": "123456789",
            "guild_count": 5,
            "member_count": 1500,
            "latency": 35
        }

        # Index template
        idx_tmpl = jinja_env.get_template("index.html")
        idx_html = idx_tmpl.render(**dummy_context)
        self.assertIn("Defend Your Discord Server", idx_html)

        # Base layout wrapping index
        base_tmpl = jinja_env.get_template("base.html")
        full_html = base_tmpl.render(content=idx_html, **dummy_context)
        self.assertIn("<!DOCTYPE html>", full_html)
        self.assertIn("TestUser", full_html)
        self.assertIn("Terms of Service", full_html)
        self.assertIn("Privacy Policy", full_html)

        # Terms template
        terms_tmpl = jinja_env.get_template("terms.html")
        terms_html = terms_tmpl.render(**dummy_context)
        self.assertIn("Agreement to Terms", terms_html)

        # Privacy template
        priv_tmpl = jinja_env.get_template("privacy.html")
        priv_html = priv_tmpl.render(**dummy_context)
        self.assertIn("SHA-256", priv_html)

        # Dashboard template
        dash_tmpl = jinja_env.get_template("dashboard.html")
        dash_html = dash_tmpl.render(guilds=[
            {"id": "999", "name": "Test Server", "icon": None, "bot_present": True}
        ], **dummy_context)
        self.assertIn("Test Server", dash_html)
        self.assertIn("Manage Security", dash_html)

class TestWebRoutes(AioHTTPTestCase):
    async def get_application(self):
        app = web.Application()
        self.bot = DummyBot()
        setup_dashboard_routes(app, self.bot)
        return app

    @unittest_run_loop
    async def test_home_page(self):
        resp = await self.client.request("GET", "/")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("Antigravity", text)
        self.assertIn("Login with Discord", text)

    @unittest_run_loop
    async def test_terms_page(self):
        resp = await self.client.request("GET", "/terms")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("Terms of Service", text)

    @unittest_run_loop
    async def test_privacy_page(self):
        resp = await self.client.request("GET", "/privacy")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("Privacy Policy", text)

    @unittest_run_loop
    async def test_dashboard_redirects_unauthenticated(self):
        resp = await self.client.request("GET", "/dashboard", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("/auth/login", resp.headers.get("Location", ""))

    @unittest_run_loop
    async def test_api_unauthorized_without_session(self):
        resp = await self.client.request("POST", "/api/guild/123/dry_run")
        self.assertEqual(resp.status, 403)

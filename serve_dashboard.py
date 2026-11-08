"""Karuppu / Wick Security Dashboard Local Server.
Runs on http://localhost:8080 and serves the web dashboard with zero external dependencies.
"""
import http.server
import os
import socketserver
import webbrowser

PORT = 8080
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # Enable CORS and disable aggressive caching for development
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

def main():
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        url = f"http://localhost:{PORT}"
        print("=" * 60)
        print(f"🚀 Karuppu Security Dashboard running at: {url}")
        print("📁 Serving directory:", DIRECTORY)
        print("🛑 Press Ctrl+C to stop the dashboard server.")
        print("=" * 60)
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server.")

if __name__ == "__main__":
    main()

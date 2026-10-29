"""Share the live scoreboard on a selected network interface.

The competition backend stays on loopback. Only the scoreboard's public
read APIs and authenticated flag submission are forwarded to it.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener


PUBLIC_GET = frozenset(("/api/scoreboard", "/api/checks", "/api/attack-data", "/health"))
MAX_BODY = 32768


def create_handler(upstream, allowed_networks):
    opener = build_opener(ProxyHandler({}))
    page = Path(__file__).with_name("scoreboard.html").read_text(encoding="utf-8")
    page = page.replace('<a href="/monitor">OPS MONITOR ↗</a>', "")

    class Handler(BaseHTTPRequestHandler):
        def send_bytes(self, status, content, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(content)

        def permitted(self):
            try:
                client = ip_address(self.client_address[0])
            except ValueError:
                return False
            return any(client in network for network in allowed_networks)

        def forward(self, method, path, data=None):
            headers = {}
            if method == "POST":
                headers["Content-Type"] = "application/json"
                authorization = self.headers.get("Authorization", "")
                if authorization:
                    headers["Authorization"] = authorization
            request = Request(upstream + path, data=data, headers=headers, method=method)
            try:
                with opener.open(request, timeout=8) as response:
                    self.send_bytes(response.status, response.read(),
                                    response.headers.get("Content-Type", "application/json"))
            except HTTPError as error:
                self.send_bytes(error.code, error.read(),
                                error.headers.get("Content-Type", "application/json"))
            except (URLError, TimeoutError, OSError):
                self.send_bytes(502, b'{"error":"Competition backend unavailable"}', "application/json")

        def do_GET(self):
            if not self.permitted():
                self.send_bytes(403, b'{"error":"Client IP not allowed"}', "application/json")
                return
            parsed = urlsplit(self.path)
            if parsed.query or parsed.path not in PUBLIC_GET | {"/"}:
                self.send_bytes(404, b'{"error":"Not found"}', "application/json")
            elif parsed.path == "/":
                self.send_bytes(200, page.encode("utf-8"), "text/html; charset=utf-8")
            else:
                self.forward("GET", parsed.path)

        def do_POST(self):
            if not self.permitted():
                self.send_bytes(403, b'{"error":"Client IP not allowed"}', "application/json")
                return
            parsed = urlsplit(self.path)
            if parsed.query or parsed.path != "/api/submit":
                self.send_bytes(404, b'{"error":"Not found"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                length = 0
            if not 0 < length <= MAX_BODY:
                self.send_bytes(413, b'{"error":"Invalid body length"}', "application/json")
                return
            self.forward("POST", parsed.path, self.rfile.read(length))

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="IPv4 address assigned to this machine")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--upstream", default="http://127.0.0.1:9000")
    parser.add_argument("--allow", action="append", required=True, help="Allowed client IPv4 address or CIDR")
    args = parser.parse_args()
    host = ip_address(args.host)
    if host.version != 4 or host.is_loopback or host.is_unspecified:
        parser.error("--host must be a non-loopback IPv4 address assigned to this machine")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    upstream = urlsplit(args.upstream)
    if upstream.scheme != "http" or upstream.hostname != "127.0.0.1" or upstream.query or upstream.fragment or upstream.path not in ("", "/"):
        parser.error("--upstream must be a loopback HTTP origin")
    networks = tuple(ip_network(value, strict=False) for value in args.allow)
    if any(network.version != 4 for network in networks):
        parser.error("--allow accepts only IPv4 addresses or CIDRs")
    networks += (ip_network(f"{host}/32"),)
    origin = f"http://127.0.0.1:{upstream.port or 80}"
    with ThreadingHTTPServer((str(host), args.port), create_handler(origin, networks)) as server:
        print(f"Scoreboard share http://{host}:{args.port}/#score", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

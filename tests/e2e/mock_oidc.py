#!/usr/bin/env python3
"""Mock OIDC / OAuth 2.0 Device Authorization Grant (RFC 8628) provider.

End-to-end test fixture for ``pam_oidc_device``: a self-contained, scenario
driven identity provider that the PAM module talks to over HTTPS (RFC 8628
device-authorization and token endpoints, OIDC UserInfo, plus a discovery
document and a /health probe).  Pure Python 3 standard library.

Endpoints
---------
POST /oauth2/device/code               RFC 8628 section 3.2 device code
POST /oauth2/token                     RFC 8628 section 3.5/3.6 token polling
GET  /oauth2/userinfo                  Bearer token -> identity claims
GET  /.well-known/openid-configuration discovery metadata (S256 advertised)
GET  /health                           liveness probe ("ok")

Scenarios
---------
Each device-code request reads the *current* content of --scenario-file
(the test harness rewrites it before every PAM attempt); unknown or empty
content falls back to ``approve-alice``.

  approve-alice       token issued on the first poll; claims map to alice
  approve-bob         token issued on the first poll; claims map to bob
  denied              token endpoint rejects the user code (access_denied)
  slowdown-approve    first token poll returns slow_down, next poll issues
  expired             token endpoint stays authorization_pending until the
                      device code's short expires_in deadline lapses

PKCE (RFC 7636) is enforced for real: a device-authorization request must
carry a code_challenge and every token request must present the matching
code_verifier (S256), otherwise the mock answers 400 invalid_grant.  The
issued access token is an unsigned (alg=none) JWT carrying iss/aud/exp/nbf
claims so the module's claims-only inspection path (verify_jwt_claims)
runs in the e2e flow.

Usage
-----
  python3 mock_oidc.py --port 8443 --cert /path/tls.crt --key /path/tls.key \
      --scenario-file /path/scenario
"""

import argparse
import base64
import datetime
import hashlib
import json
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# (scenario, local_user, expires_in, first_poll, second_poll)
SCENARIOS = {
    "approve-alice": ("alice", 300, "token", None),
    "approve-bob": ("bob", 300, "token", None),
    "denied": ("alice", 300, "denied", None),
    "slowdown-approve": ("alice", 300, "slow_down", "token"),
    "expired": ("alice", 6, "pending", None),
}
DEFAULT_SCENARIO = "approve-alice"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(issuer: str, audience: str, sub: str, local_user: str) -> str:
    """Unsigned (alg=none) JWT; the module inspects claims only, never signatures."""
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 300,
        "preferred_username": f"{local_user}@sandbox.test",
        "email": f"{local_user}@sandbox.test",
        "groups": ["e2e-ops"],
    }
    seg = b64url(json.dumps(header, separators=(",", ":")).encode())
    seg += "." + b64url(json.dumps(payload, separators=(",", ":")).encode())
    return seg + "."


class MockOIDC:
    """Holds device-code state shared between the threaded request handlers."""

    def __init__(self, port: int, scenario_file: str, issuer: str, audience: str):
        self.port = port
        self.scenario_file = scenario_file
        self.issuer = issuer
        self.audience = audience
        self.lock = threading.Lock()
        # device_code -> {"scenario", "challenge", "user_code", "local_user",
        #                 "sub", "token", "polls"}
        self.codes = {}

    def read_scenario(self) -> str:
        try:
            with open(self.scenario_file, "r", encoding="ascii") as handle:
                value = handle.read().strip()
        except OSError:
            value = ""
        return value if value in SCENARIOS else DEFAULT_SCENARIO

    def issue(self, form: dict) -> dict:
        scenario = self.read_scenario()
        local_user, expires_in, _, _ = SCENARIOS[scenario]
        device_code = "dc-" + uuid.uuid4().hex[:16]
        user_code = "E2E-" + uuid.uuid4().hex[:4].upper()
        sub = "e2e-sub-" + uuid.uuid4().hex[:8]
        entry = {
            "scenario": scenario,
            "challenge": form.get("code_challenge", [None])[0],
            "user_code": user_code,
            "local_user": local_user,
            "sub": sub,
            "token": None,
            "polls": 0,
        }
        with self.lock:
            self.codes[device_code] = entry
        log_request(f"device-code issued: scenario={scenario} user_code={user_code} "
                    f"pkce={'yes' if entry['challenge'] else 'no'}")
        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": f"https://127.0.0.1:{self.port}/verify",
            "verification_uri_complete": f"https://127.0.0.1:{self.port}/verify?user_code={user_code}",
            "expires_in": expires_in,
            "interval": 5,
        }

    def identity(self, local_user: str, sub: str) -> dict:
        return {
            "sub": sub,
            "preferred_username": f"{local_user}@sandbox.test",
            "email": f"{local_user}@sandbox.test",
            "groups": ["e2e-ops"],
        }

    def poll_token(self, form: dict) -> tuple:
        """One token-endpoint poll. Returns (status_code, json_body)."""
        device_code = form.get("device_code", [None])[0]
        grant_type = form.get("grant_type", [None])[0]
        verifier = form.get("code_verifier", [None])[0]
        if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
            return 400, {"error": "unsupported_grant_type"}
        with self.lock:
            entry = self.codes.get(device_code or "")
            if entry is None:
                return 400, {"error": "invalid_grant", "error_description": "unknown device_code"}
            # RFC 7636: the verifier must re-derive the stored S256 challenge.
            if entry["challenge"]:
                digest = b64url(hashlib.sha256((verifier or "").encode("utf-8")).digest()) if verifier else None
                if digest != entry["challenge"]:
                    log_request(f"token poll rejected: PKCE S256 verifier mismatch "
                                f"(challenge present, verifier {'sent' if verifier else 'missing'})")
                    return 400, {"error": "invalid_grant",
                                 "error_description": "code_verifier does not match code_challenge"}
            entry["polls"] += 1
            polls, scenario = entry["polls"], entry["scenario"]
            if entry["token"] is None:
                entry["token"] = make_jwt(self.issuer, self.audience, entry["sub"], entry["local_user"])

        _, _, first_poll, second_poll = SCENARIOS[scenario]
        step = second_poll if polls >= 2 and second_poll else first_poll
        log_request(f"token poll {polls} [{scenario}] -> {step}")
        if step == "token":
            body = {"access_token": entry["token"],
                    "id_token": entry["token"],
                    "token_type": "Bearer",
                    "expires_in": 3600}
            return 200, body
        if step == "denied":
            return 400, {"error": "access_denied", "error_description": "user denied the device code"}
        if step == "slow_down":
            return 400, {"error": "slow_down"}
        return 400, {"error": "authorization_pending"}

    def userinfo(self, bearer_token):
        with self.lock:
            for entry in self.codes.values():
                if entry["token"] == bearer_token:
                    return 200, self.identity(entry["local_user"], entry["sub"])
        return 401, {"error": "invalid_token"}


_LOG_LOCK = threading.Lock()


def log_request(message: str) -> None:
    with _LOG_LOCK:
        print(f"[mock-oidc] {message}", flush=True)


class Handler(BaseHTTPRequestHandler):
    """Routes the mock provider's HTTP endpoints onto the MockOIDC state."""

    server_version = "MockOIDC/1.0"
    mock: MockOIDC = None  # type: ignore  # set in main()

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return urllib.parse.parse_qs(raw, keep_blank_values=True)

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        if self.path == "/oauth2/device/code":
            self._send_json(200, self.mock.issue(self._read_form()))
        elif self.path == "/oauth2/token":
            status, body = self.mock.poll_token(self._read_form())
            self._send_json(status, body)
        else:
            self._send_json(404, {"error": "not_found"})

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/oauth2/userinfo":
            auth = self.headers.get("Authorization") or ""
            token = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
            status, body = self.mock.userinfo(token)
            log_request(f"userinfo request -> {status}")
            self._send_json(status, body)
        elif self.path == "/.well-known/openid-configuration":
            base = f"https://127.0.0.1:{self.mock.port}"
            self._send_json(200, {
                "issuer": self.mock.issuer,
                "device_authorization_endpoint": f"{base}/oauth2/device/code",
                "token_endpoint": f"{base}/oauth2/token",
                "userinfo_endpoint": f"{base}/oauth2/userinfo",
                "code_challenge_methods_supported": ["S256"],
            })
        else:
            self._send_json(404, {"error": "not_found"})

    def log_message(self, fmt, *args) -> None:  # noqa: N802 (http.server API)
        log_request(f"{self.address_string()} {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", required=True, help="PEM certificate (SAN: 127.0.0.1)")
    parser.add_argument("--key", required=True, help="PEM private key")
    parser.add_argument("--scenario-file", required=True,
                        help="text file whose current content selects the scenario")
    parser.add_argument("--issuer", default=None,
                        help="iss claim value (default: https://127.0.0.1:<port>)")
    parser.add_argument("--audience", default="urn:pam-oidc-device:e2e")
    args = parser.parse_args()

    import ssl

    issuer = args.issuer or f"https://127.0.0.1:{args.port}"
    mock = MockOIDC(args.port, args.scenario_file, issuer, args.audience)
    Handler.mock = mock

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    log_request(f"ready: https://127.0.0.1:{args.port} (issuer={issuer}, aud={args.audience})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

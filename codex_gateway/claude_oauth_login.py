from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx

from .config import settings
from .claude_oauth import ClaudeOAuthCreds

_AUTH_URL = "https://claude.ai/oauth/authorize"
_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
_DEFAULT_SCOPE = "org:create_api_key user:profile user:inference"


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _pkce_codes() -> tuple[str, str]:
    verifier = _b64url_no_pad(secrets.token_bytes(64))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class _CallbackState:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.code: str | None = None
        self.state: str | None = None
        self.error: str | None = None


def _make_handler(cb: _CallbackState, expected_state: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return

            qs = urllib.parse.parse_qs(parsed.query)
            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [None])[0]
            err = (qs.get("error") or [None])[0]

            if err:
                cb.error = str(err)
            elif not code:
                cb.error = "missing_code"
            elif state != expected_state:
                cb.error = "state_mismatch"
            else:
                cb.code = str(code)
                cb.state = str(state)

            cb.event.set()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            msg = "OK — you can close this tab." if cb.error is None else f"Error: {cb.error}"
            self.wfile.write(
                (
                    "<!doctype html><meta charset='utf-8'/>"
                    "<title>Claude OAuth</title>"
                    f"<p>{msg}</p>"
                ).encode("utf-8")
            )

    return Handler


def _save_creds(path: Path, creds: ClaudeOAuthCreds) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {}
    if creds.access_token:
        payload["access_token"] = creds.access_token
    if creds.refresh_token:
        payload["refresh_token"] = creds.refresh_token
    if creds.expires_at_s is not None:
        payload["expires_at_s"] = int(creds.expires_at_s)
    if creds.token_type:
        payload["token_type"] = creds.token_type
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass


def login(
    *,
    port: int,
    oauth_client_id: str,
    scope: str,
    creds_path: Path,
    open_browser: bool,
    timeout_s: int,
) -> Path:
    verifier, challenge = _pkce_codes()
    state = secrets.token_urlsafe(16)
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    params = {
        "code": "true",
        "client_id": oauth_client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    url = f"{_AUTH_URL}?{urllib.parse.urlencode(params)}"

    cb = _CallbackState()
    handler = _make_handler(cb, state)
    server = HTTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        print(f"[claude-oauth] Redirect URI: {redirect_uri}")
        print(f"[claude-oauth] Open this URL to authorize:\n{url}\n")
        if open_browser:
            webbrowser.open(url)

        if not cb.event.wait(timeout=timeout_s):
            raise RuntimeError("Timeout waiting for OAuth callback")
        if cb.error:
            raise RuntimeError(f"OAuth callback error: {cb.error}")
        if not cb.code:
            raise RuntimeError("OAuth callback missing code")

        payload = {
            "code": cb.code,
            "state": state,
            "grant_type": "authorization_code",
            "client_id": oauth_client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        with httpx.Client(timeout=min(timeout_s, 30)) as client:
            resp = client.post(_TOKEN_URL, json=payload, headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError("Token exchange returned non-JSON object")

        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        expires_in = data.get("expires_in")
        token_type = data.get("token_type") or "Bearer"
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("Token exchange missing access_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise RuntimeError("Token exchange missing refresh_token")
        expires_at_s = None
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expires_at_s = int(time.time() + int(expires_in))

        _save_creds(
            creds_path,
            ClaudeOAuthCreds(access_token=access_token, refresh_token=refresh_token, expires_at_s=expires_at_s, token_type=str(token_type)),
        )
        return creds_path
    finally:
        server.shutdown()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="claude-oauth-login")
    parser.add_argument("--port", type=int, default=54545)
    parser.add_argument("--scope", default=_DEFAULT_SCOPE)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--creds-path", default=settings.claude_oauth_creds_path)
    args = parser.parse_args(argv)

    oauth_client_id = settings.claude_oauth_client_id or "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    path = login(
        port=args.port,
        oauth_client_id=oauth_client_id,
        scope=args.scope,
        creds_path=Path(args.creds_path).expanduser(),
        open_browser=not args.no_browser,
        timeout_s=5 * 60,
    )
    print(f"[claude-oauth] Saved: {path}")


if __name__ == "__main__":
    main()


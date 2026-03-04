import json

import pytest

from mcp_ip_guard.middleware import IpGuardMiddleware


def _make_scope(
    path: str = "/mcp",
    client_ip: str = "8.8.8.8",
    xff: str | None = None,
    scope_type: str = "http",
) -> dict[str, object]:
    headers: list[tuple[bytes, bytes]] = []
    if xff:
        headers.append((b"x-forwarded-for", xff.encode()))
    return {
        "type": scope_type,
        "path": path,
        "client": (client_ip, 12345),
        "headers": headers,
    }


class _Capture:
    """Captures ASGI send() calls."""

    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []
        self.app_called = False
        self.receive_called = False

    async def app(self, scope: dict[str, object], receive: object, send: object) -> None:
        self.app_called = True

    async def send(self, message: dict[str, object]) -> None:
        self.messages.append(message)

    async def receive(self) -> dict[str, object]:
        self.receive_called = True
        return {"type": "websocket.connect"}


@pytest.mark.asyncio
async def test_blocks_disallowed_ip() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/mcp", client_ip="8.8.8.8")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is False
    assert len(cap.messages) == 2
    assert cap.messages[0]["status"] == 403
    body = json.loads(cap.messages[1]["body"])  # type: ignore[arg-type]
    assert body["error"] == "Access denied"


@pytest.mark.asyncio
async def test_allows_openai_ip() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/mcp", xff="52.173.123.5")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is True
    assert len(cap.messages) == 0


@pytest.mark.asyncio
async def test_passes_through_unprotected_paths() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/health", client_ip="8.8.8.8")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is True


@pytest.mark.asyncio
async def test_passes_through_non_http_non_websocket() -> None:
    """Scopes that are neither http nor websocket pass through."""
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope: dict[str, object] = {"type": "lifespan", "path": "/mcp"}
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is True


@pytest.mark.asyncio
async def test_custom_protected_paths() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(
        cap.app,
        protected_paths=["/api/v1"],
        allow_localhost_in_dev=False,
    )

    # /mcp should pass through now
    scope1 = _make_scope(path="/mcp", client_ip="8.8.8.8")
    await mw(scope1, None, cap.send)  # type: ignore[arg-type]
    assert cap.app_called is True

    # /api/v1 should be blocked
    cap2 = _Capture()
    scope2 = _make_scope(path="/api/v1", client_ip="8.8.8.8")
    await mw(scope2, None, cap2.send)  # type: ignore[arg-type]
    assert cap2.messages[0]["status"] == 403


# --- Security fix tests ---


@pytest.mark.asyncio
async def test_trailing_slash_does_not_bypass() -> None:
    """Requesting /mcp/ should still be guarded when /mcp is protected."""
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/mcp/", client_ip="8.8.8.8")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is False
    assert cap.messages[0]["status"] == 403


@pytest.mark.asyncio
async def test_trailing_slash_on_messages_does_not_bypass() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/mcp/messages/", client_ip="8.8.8.8")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is False
    assert cap.messages[0]["status"] == 403


@pytest.mark.asyncio
async def test_websocket_blocked_on_protected_path() -> None:
    """WebSocket connections to protected paths should be IP-checked."""
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/mcp", client_ip="8.8.8.8", scope_type="websocket")
    await mw(scope, cap.receive, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is False
    assert cap.receive_called is True
    # Should send websocket.close with code 1008 (Policy Violation)
    assert len(cap.messages) == 1
    assert cap.messages[0]["type"] == "websocket.close"
    assert cap.messages[0]["code"] == 1008


@pytest.mark.asyncio
async def test_websocket_allowed_for_openai_ip() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/mcp", xff="52.173.123.5", scope_type="websocket")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is True


@pytest.mark.asyncio
async def test_websocket_passes_through_unprotected_paths() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope = _make_scope(path="/health", client_ip="8.8.8.8", scope_type="websocket")
    await mw(scope, None, cap.send)  # type: ignore[arg-type]

    assert cap.app_called is True

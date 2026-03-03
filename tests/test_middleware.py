import json

import pytest

from mcp_ip_guard.middleware import IpGuardMiddleware


def _make_scope(
    path: str = "/mcp",
    client_ip: str = "8.8.8.8",
    xff: str | None = None,
) -> dict[str, object]:
    headers: list[tuple[bytes, bytes]] = []
    if xff:
        headers.append((b"x-forwarded-for", xff.encode()))
    return {
        "type": "http",
        "path": path,
        "client": (client_ip, 12345),
        "headers": headers,
    }


class _Capture:
    """Captures ASGI send() calls."""

    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []
        self.app_called = False

    async def app(self, scope: dict[str, object], receive: object, send: object) -> None:
        self.app_called = True

    async def send(self, message: dict[str, object]) -> None:
        self.messages.append(message)


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
async def test_passes_through_non_http() -> None:
    cap = _Capture()
    mw = IpGuardMiddleware(cap.app, allow_localhost_in_dev=False)

    scope: dict[str, object] = {"type": "websocket", "path": "/mcp"}
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

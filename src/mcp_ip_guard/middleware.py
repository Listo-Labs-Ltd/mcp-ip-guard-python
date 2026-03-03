"""ASGI middleware for IP allowlist enforcement on MCP endpoints."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence

from mcp_ip_guard.guard import IpGuard, IpGuardOptions


class IpGuardMiddleware:
    """ASGI middleware that blocks requests from IPs not in the allowlist.

    Only guards the specified ``protected_paths``. All other paths pass through.

    Example with Starlette / FastAPI::

        from starlette.applications import Starlette
        from mcp_ip_guard.middleware import IpGuardMiddleware

        app = Starlette(...)
        app.add_middleware(
            IpGuardMiddleware,
            protected_paths=["/mcp", "/mcp/messages"],
        )

    Example with custom options::

        app.add_middleware(
            IpGuardMiddleware,
            protected_paths=["/mcp", "/mcp/messages"],
            include_azure_ranges=True,
            additional_ranges=["10.0.0.0/8"],
            on_blocked=lambda ip, path: print(f"Blocked {ip}"),
        )
    """

    def __init__(
        self,
        app: object,
        *,
        protected_paths: Sequence[str] = ("/mcp", "/mcp/messages"),
        include_openai_ranges: bool = True,
        include_azure_ranges: bool = False,
        additional_ranges: Sequence[str] = (),
        allow_localhost_in_dev: bool = True,
        debug: bool = False,
        on_blocked: Callable[[str, str], None] | None = None,
    ) -> None:
        self.app = app
        self.protected_paths = set(protected_paths)
        self.guard = IpGuard(
            IpGuardOptions(
                include_openai_ranges=include_openai_ranges,
                include_azure_ranges=include_azure_ranges,
                additional_ranges=list(additional_ranges),
                allow_localhost_in_dev=allow_localhost_in_dev,
                debug=debug,
                on_blocked=on_blocked,
            )
        )

    async def __call__(
        self,
        scope: dict[str, object],
        receive: object,
        send: object,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)  # type: ignore[operator]
            return

        path: str = scope.get("path", "")  # type: ignore[assignment]
        if path not in self.protected_paths:
            await self.app(scope, receive, send)  # type: ignore[operator]
            return

        client_ip = self.guard.get_client_ip(scope)  # type: ignore[arg-type]
        result = self.guard.check_request(client_ip, path)

        if not result.allowed:
            body = json.dumps(
                {
                    "error": "Access denied",
                    "message": "This endpoint only accepts requests from allowed IPs",
                }
            ).encode()

            await send(
                {  # type: ignore[operator]
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(body)).encode()],
                    ],
                }
            )
            await send(
                {  # type: ignore[operator]
                    "type": "http.response.body",
                    "body": body,
                }
            )
            return

        await self.app(scope, receive, send)  # type: ignore[operator]

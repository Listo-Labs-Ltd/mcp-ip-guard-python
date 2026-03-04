"""IP allowlist guard for MCP servers."""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from mcp_ip_guard.ranges import OPENAI_IP_RANGES

logger = logging.getLogger("mcp_ip_guard")


@dataclass(frozen=True)
class GuardResult:
    """Result of checking a request against the guard."""

    allowed: bool
    client_ip: str


@dataclass
class IpGuardOptions:
    """Configuration for creating an IP guard.

    Args:
        include_openai_ranges: Include OpenAI/ChatGPT egress IP ranges. Default True.
        include_azure_ranges: Include Microsoft Azure public cloud IP ranges.
            Enable for ChatGPT developer mode where requests route through Azure.
            Default False.
        include_fastly_ranges: Include Fastly CDN public IP ranges. OpenAI uses
            Fastly as their edge CDN — in ChatGPT developer mode, requests may
            arrive from Fastly edge IPs (e.g. 140.248.x.x). Default False.
        include_anthropic_ranges: Include Anthropic (Claude) outbound IP ranges.
            Enable when your MCP server receives tool calls from Claude.
            Default False.
        additional_ranges: Extra CIDR ranges or single IPs to allow.
            Single IPs without a prefix are treated as /32.
        allow_localhost_in_dev: Allow localhost when not in production. Default True.
            Checks the environment variable ``ENVIRONMENT`` (or ``NODE_ENV`` as
            fallback) — localhost is only bypassed when the value is NOT
            ``"production"``.
        trusted_proxy_depth: Number of trusted reverse proxies in front of the
            application. The client IP is extracted from
            ``X-Forwarded-For[-depth]``. Default 1 (single proxy like Railway
            or Cloudflare). Set to 2 for CDN -> Load Balancer -> App, etc.
        debug: Log blocked IPs to stdout. Default False.
        on_blocked: Optional callback ``(client_ip, path) -> None`` invoked when
            a request is blocked. Useful for recording telemetry.
    """

    include_openai_ranges: bool = True
    include_azure_ranges: bool = False
    include_fastly_ranges: bool = False
    include_anthropic_ranges: bool = False
    additional_ranges: Sequence[str] = field(default_factory=list)
    allow_localhost_in_dev: bool = True
    trusted_proxy_depth: int = 1
    debug: bool = False
    on_blocked: Callable[[str, str], None] | None = None


_LOCALHOST_ADDRS = frozenset({"127.0.0.1", "::1"})


def _is_production() -> bool:
    env = os.environ.get("ENVIRONMENT") or os.environ.get("NODE_ENV") or ""
    return env.lower() == "production"


def _normalise_cidr(cidr: str) -> str:
    return cidr if "/" in cidr else f"{cidr}/32"


class IpGuard:
    """IP allowlist guard for protecting MCP server endpoints.

    By default includes all known OpenAI/ChatGPT egress IPs.
    Extend the allowlist with ``additional_ranges`` or enable
    ``include_azure_ranges`` for ChatGPT developer mode.

    Example::

        from mcp_ip_guard import create_ip_guard

        guard = create_ip_guard()

        # Check a raw IP
        if guard.is_allowed("52.173.123.5"):
            print("Allowed")

        # In a Starlette / FastAPI handler
        from starlette.requests import Request
        client_ip = guard.get_client_ip(request)
    """

    __slots__ = (
        "_networks",
        "_allow_localhost",
        "_trusted_proxy_depth",
        "_debug",
        "_on_blocked",
    )

    def __init__(self, options: IpGuardOptions | None = None) -> None:
        opts = options or IpGuardOptions()

        # Build list of CIDR strings
        all_ranges: list[str] = []
        if opts.include_openai_ranges:
            all_ranges.extend(OPENAI_IP_RANGES)
        if opts.include_azure_ranges:
            from mcp_ip_guard.azure_ranges import AZURE_IP_RANGES

            all_ranges.extend(AZURE_IP_RANGES)
        if opts.include_fastly_ranges:
            from mcp_ip_guard.fastly_ranges import FASTLY_IP_RANGES

            all_ranges.extend(FASTLY_IP_RANGES)
        if opts.include_anthropic_ranges:
            from mcp_ip_guard.anthropic_ranges import ANTHROPIC_IP_RANGES

            all_ranges.extend(ANTHROPIC_IP_RANGES)
        for r in opts.additional_ranges:
            all_ranges.append(_normalise_cidr(r))

        # Pre-parse into IPv4Network objects for fast matching
        networks: list[ipaddress.IPv4Network] = []
        for cidr in all_ranges:
            try:
                networks.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError:
                logger.warning("Skipping invalid CIDR: %s", cidr)
        self._networks: tuple[ipaddress.IPv4Network, ...] = tuple(networks)

        # Evaluate production check once at init time, not on every request
        self._allow_localhost = opts.allow_localhost_in_dev and not _is_production()
        self._trusted_proxy_depth = max(1, opts.trusted_proxy_depth)
        self._debug = opts.debug
        self._on_blocked = opts.on_blocked

    @property
    def range_count(self) -> int:
        """Total number of parsed CIDR ranges in the allowlist."""
        return len(self._networks)

    def is_allowed(self, ip: str) -> bool:
        """Check if a raw IP address string is in the allowlist."""
        stripped = ip.strip()

        # Localhost bypass for development (evaluated once at init)
        if self._allow_localhost and stripped in _LOCALHOST_ADDRS:
            return True

        # Normalise via ipaddress to handle all IPv6-mapped-IPv4 forms
        # (e.g. ::ffff:1.2.3.4, ::FFFF:1.2.3.4, ::ffff:102:304)
        try:
            parsed = ipaddress.ip_address(stripped)
        except ValueError:
            return False  # Unparseable -> deny

        # Extract the IPv4 address (handles IPv4-mapped IPv6 transparently)
        if isinstance(parsed, ipaddress.IPv6Address):
            mapped = parsed.ipv4_mapped
            if mapped is None:
                return False  # Pure IPv6 not supported -> deny
            addr = mapped
        else:
            addr = parsed

        for network in self._networks:
            if addr in network:
                return True
        return False

    @staticmethod
    def get_client_ip_from_headers(
        remote_addr: str | None,
        x_forwarded_for: str | None,
        trusted_proxy_depth: int = 1,
    ) -> str:
        """Extract client IP from raw header values.

        Uses ``X-Forwarded-For[-trusted_proxy_depth]`` to select the IP
        added by the outermost trusted proxy. With a single proxy (the
        default), this is the rightmost entry. With two proxies (e.g.
        CDN -> Load Balancer -> App), use ``trusted_proxy_depth=2`` to
        skip the inner proxy's entry.
        """
        if x_forwarded_for:
            ips = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
            if ips:
                idx = min(trusted_proxy_depth, len(ips))
                return ips[-idx]
        return remote_addr or "unknown"

    def get_client_ip(self, scope: dict[str, object]) -> str:
        """Extract client IP from an ASGI scope dict or Starlette-like request.

        Works with raw ASGI scope dicts and any object that has a ``.scope``
        attribute (Starlette Request, FastAPI Request, etc.).
        """
        # If it's a Starlette/FastAPI Request, unwrap to scope
        actual_scope: dict[str, object] = scope
        if hasattr(scope, "scope"):
            actual_scope = scope.scope  # type: ignore[union-attr]

        # Get headers from scope
        raw_headers: list[tuple[bytes, bytes]] = actual_scope.get("headers", [])  # type: ignore[assignment]
        xff: str | None = None
        for name, value in raw_headers:
            if name.lower() == b"x-forwarded-for":
                xff = value.decode("latin-1")
                break

        # Get remote address from scope
        client: tuple[str, int] | None = actual_scope.get("client")  # type: ignore[assignment]
        remote = client[0] if client else None

        return self.get_client_ip_from_headers(remote, xff, self._trusted_proxy_depth)

    def check_request(
        self,
        client_ip: str,
        path: str = "unknown",
    ) -> GuardResult:
        """Check if a client IP is allowed.

        Returns a ``GuardResult`` and fires the ``on_blocked`` callback
        if the IP is denied.
        """
        if not self.is_allowed(client_ip):
            if self._debug:
                logger.info("[mcp-ip-guard] Blocked IP: %s on %s", client_ip, path)

            if self._on_blocked:
                try:
                    self._on_blocked(client_ip, path)
                except Exception:
                    logger.exception("on_blocked callback failed for %s", client_ip)

            return GuardResult(allowed=False, client_ip=client_ip)

        return GuardResult(allowed=True, client_ip=client_ip)


def create_ip_guard(
    *,
    include_openai_ranges: bool = True,
    include_azure_ranges: bool = False,
    include_fastly_ranges: bool = False,
    include_anthropic_ranges: bool = False,
    additional_ranges: Sequence[str] = (),
    allow_localhost_in_dev: bool = True,
    trusted_proxy_depth: int = 1,
    debug: bool = False,
    on_blocked: Callable[[str, str], None] | None = None,
) -> IpGuard:
    """Create an IP allowlist guard for protecting MCP server endpoints.

    Convenience factory that mirrors the Node.js ``createIpGuard()`` API.

    Example::

        from mcp_ip_guard import create_ip_guard

        guard = create_ip_guard()
        assert guard.is_allowed("52.173.123.5")

    Example with Azure ranges for ChatGPT developer mode::

        guard = create_ip_guard(include_azure_ranges=True)

    Example with custom ranges and telemetry hook::

        guard = create_ip_guard(
            additional_ranges=["10.0.0.0/8", "192.168.1.100"],
            on_blocked=lambda ip, path: print(f"Blocked {ip} on {path}"),
        )
    """
    return IpGuard(
        IpGuardOptions(
            include_openai_ranges=include_openai_ranges,
            include_azure_ranges=include_azure_ranges,
            include_fastly_ranges=include_fastly_ranges,
            include_anthropic_ranges=include_anthropic_ranges,
            additional_ranges=list(additional_ranges),
            allow_localhost_in_dev=allow_localhost_in_dev,
            trusted_proxy_depth=trusted_proxy_depth,
            debug=debug,
            on_blocked=on_blocked,
        )
    )

from mcp_ip_guard.guard import (
    GuardResult,
    IpGuard,
    IpGuardOptions,
    create_ip_guard,
)
from mcp_ip_guard.ranges import OPENAI_IP_RANGES

__all__ = [
    "IpGuard",
    "IpGuardOptions",
    "GuardResult",
    "create_ip_guard",
    "OPENAI_IP_RANGES",
    "get_azure_ip_ranges",
    "IpGuardMiddleware",
]


def get_azure_ip_ranges() -> tuple[str, ...]:
    """Lazy accessor for Azure IP ranges to avoid loading 10K+ entries on import."""
    from mcp_ip_guard.azure_ranges import AZURE_IP_RANGES

    return AZURE_IP_RANGES


def IpGuardMiddleware(  # noqa: N802
    app: object,
    **kwargs: object,
) -> object:
    """Lazy accessor for ASGI middleware to avoid import errors without starlette."""
    from mcp_ip_guard.middleware import IpGuardMiddleware as Middleware  # noqa: N811

    return Middleware(app, **kwargs)  # type: ignore[arg-type]

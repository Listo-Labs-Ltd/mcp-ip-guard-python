# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

### [0.2.0](https://github.com/Listo-Labs-Ltd/mcp-ip-guard-python/compare/v0.1.0...v0.2.0) 2026-03-04

- Security: Middleware now guards WebSocket connections on protected paths (previously only HTTP scopes were checked, allowing full bypass via WebSocket)
- Security: Middleware normalizes request paths by stripping trailing slashes before matching — `/mcp/` no longer bypasses `/mcp`
- Security: Added `trusted_proxy_depth` parameter (default: 1) to `create_ip_guard()` and `IpGuardMiddleware` — controls which `X-Forwarded-For` entry is used as the client IP, preventing misidentification in multi-proxy deployments
- Security: Removed `"localhost"` string from the localhost bypass set — no ASGI server reports client addresses as the literal string `"localhost"`, and it was injectable via `X-Forwarded-For`
- Security: Production environment check (`ENVIRONMENT`/`NODE_ENV`) is now evaluated once at init time instead of on every request
- Security: IP addresses are now normalized via `ipaddress.ip_address()` — handles uppercase `::FFFF:`, hex-form IPv4-mapped IPv6, and leading/trailing whitespace
- Security: `on_blocked` callback exceptions are now caught and logged instead of propagating (which would suppress the deny response)
- Added: `trusted_proxy_depth` option to `create_ip_guard()`, `IpGuardOptions`, and `IpGuardMiddleware`
- Added: WebSocket close code `1008` (Policy Violation) for blocked WebSocket connections
- Changed: `get_client_ip_from_headers()` now accepts an optional `trusted_proxy_depth` parameter

### [0.1.0](https://github.com/Listo-Labs-Ltd/mcp-ip-guard-python/releases/tag/v0.1.0) 2026-03-03

- Initial release
- IP allowlist guard with OpenAI/ChatGPT egress IP ranges
- Optional Azure public cloud IP ranges for ChatGPT developer mode
- ASGI middleware for Starlette/FastAPI
- Zero production dependencies

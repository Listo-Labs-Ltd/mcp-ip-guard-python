# listo-mcp-ip-guard

IP allowlist guard for Python MCP servers. Ships with OpenAI/ChatGPT egress IP ranges and Microsoft Azure public cloud ranges for ChatGPT developer mode. Zero production dependencies.

## Install

```bash
pip install listo-mcp-ip-guard
```

## Quick Start

```python
from mcp_ip_guard import create_ip_guard

# Creates a guard with all OpenAI/ChatGPT IPs pre-loaded
guard = create_ip_guard()

# Check a raw IP
if guard.is_allowed("52.173.123.5"):
    print("Allowed")
```

## Options

```python
guard = create_ip_guard(
    # Include OpenAI/ChatGPT egress IPs (default: True)
    include_openai_ranges=True,

    # Include Azure public cloud IPs for ChatGPT developer mode (default: False)
    include_azure_ranges=False,

    # Add your own IPs/CIDR ranges
    additional_ranges=[
        "10.0.0.0/8",        # CIDR range
        "192.168.1.100",     # Single IP (treated as /32)
    ],

    # Allow localhost in non-production (default: True)
    allow_localhost_in_dev=True,

    # Number of trusted reverse proxies (default: 1)
    # Uses X-Forwarded-For[-depth] to extract the client IP
    trusted_proxy_depth=1,

    # Log blocked IPs (default: False)
    debug=False,

    # Hook for telemetry / custom logging
    on_blocked=lambda ip, path: print(f"Blocked {ip} on {path}"),
)
```

## API

### `create_ip_guard(**options) -> IpGuard`

Creates a new guard instance.

### `guard.is_allowed(ip: str) -> bool`

Check if a raw IP address string is in the allowlist.

### `guard.get_client_ip(scope) -> str`

Extract the client IP from an ASGI scope dict or Starlette/FastAPI Request. Uses `X-Forwarded-For[-trusted_proxy_depth]` to select the IP added by the outermost trusted proxy.

### `guard.get_client_ip_from_headers(remote_addr, x_forwarded_for, trusted_proxy_depth=1) -> str`

Extract client IP from raw header values. Static method.

### `guard.check_request(client_ip, path) -> GuardResult`

Check if a client IP is allowed. Fires the `on_blocked` callback if denied. Returns `GuardResult(allowed=bool, client_ip=str)`.

### `guard.range_count -> int`

Total number of parsed CIDR ranges in the allowlist.

### `OPENAI_IP_RANGES`

The raw tuple of OpenAI/ChatGPT egress IP ranges in CIDR notation.

### `AZURE_IP_RANGES`

Microsoft Azure public cloud IPv4 ranges (10,360 CIDRs). Lazy-loaded on first access.

## ASGI Middleware (Starlette / FastAPI)

```python
from starlette.applications import Starlette
from mcp_ip_guard.middleware import IpGuardMiddleware

app = Starlette(...)
app.add_middleware(
    IpGuardMiddleware,
    protected_paths=["/mcp", "/mcp/messages"],
)
```

With Azure ranges for developer mode:

```python
app.add_middleware(
    IpGuardMiddleware,
    protected_paths=["/mcp", "/mcp/messages"],
    include_azure_ranges=True,
)
```

The middleware guards both HTTP and WebSocket connections on the specified `protected_paths`. All other paths pass through unblocked. Paths are normalized (trailing slashes stripped) before matching.

With multi-proxy setup (e.g. CDN -> Load Balancer -> App):

```python
app.add_middleware(
    IpGuardMiddleware,
    protected_paths=["/mcp", "/mcp/messages"],
    trusted_proxy_depth=2,  # skip the inner proxy's XFF entry
)
```

## Usage with Python MCP Server

```python
from mcp.server.fastmcp import FastMCP
from mcp_ip_guard import create_ip_guard

guard = create_ip_guard(
    debug=True,
    on_blocked=lambda ip, path: print(f"Blocked {ip} on {path}"),
)

mcp = FastMCP("my-server")

# In your custom HTTP handler or middleware:
client_ip = guard.get_client_ip(request)
result = guard.check_request(client_ip, request.url.path)
if not result.allowed:
    return JSONResponse({"error": "Access denied"}, status_code=403)
```

## ChatGPT Developer Mode

When connecting an MCP server directly to ChatGPT in developer mode, requests may come from Azure infrastructure IPs rather than the dedicated OpenAI egress IPs. Enable `include_azure_ranges` to allow these:

```python
guard = create_ip_guard(include_azure_ranges=True)
```

This adds ~10,360 Azure IPv4 CIDR ranges to the allowlist. Only enable this when you need developer-mode compatibility — in production with ChatGPT's public integration, the default OpenAI ranges are sufficient.

## Reverse Proxy Configuration

The guard extracts the client IP from the `X-Forwarded-For` header using `trusted_proxy_depth` to select the correct entry. The default (`1`) works for single-proxy deployments (e.g. Railway, Cloudflare, or a single load balancer).

| Deployment | Depth | XFF example | Extracted IP |
|---|---|---|---|
| Single proxy (Cloudflare -> App) | 1 | `client, cloudflare` | `cloudflare` entry = client IP added by Cloudflare |
| Two proxies (CDN -> LB -> App) | 2 | `client, cdn, lb` | `cdn` entry = client IP added by CDN |
| Direct (no proxy) | 1 | _(empty)_ | Falls back to `remote_addr` |

Set `trusted_proxy_depth` to match the number of trusted reverse proxies in front of your application. An incorrect value means the guard checks the wrong IP.

## Environment

- `ENVIRONMENT` (or `NODE_ENV` as fallback) — When set to `"production"`, localhost is blocked (unless `allow_localhost_in_dev=False`).

## IP Ranges Sources

- **OpenAI** — Published egress IPs (2026-02-21). Includes /28, /26, and /32 entries covering all ChatGPT outbound traffic to MCP servers.
- **Azure** — Microsoft Azure Service Tags – Public Cloud (2026-03-02). The `AzureCloud` service tag with 10,360 IPv4 CIDR ranges covering all Azure datacenter egress.

## License

MIT

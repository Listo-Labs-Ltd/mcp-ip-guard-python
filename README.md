# listo-mcp-ip-guard

IP allowlist guard for Python MCP servers. Ships with OpenAI/ChatGPT egress IP ranges, Anthropic/Claude outbound IPs, Fastly CDN ranges, and Microsoft Azure public cloud ranges for ChatGPT developer mode. Zero production dependencies.

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

    # Include Fastly CDN IPs — OpenAI's edge CDN (default: False)
    include_fastly_ranges=False,

    # Include Anthropic/Claude outbound IPs (default: False)
    include_anthropic_ranges=False,

    # Add your own IPs/CIDR ranges
    additional_ranges=[
        "10.0.0.0/8",        # CIDR range
        "192.168.1.100",     # Single IP (treated as /32)
    ],

    # Allow localhost in non-production (default: True)
    allow_localhost_in_dev=True,

    # Number of trusted reverse proxies (default: 1)
    # See "Reverse Proxy Configuration" section below
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

### `get_azure_ip_ranges() -> tuple[str, ...]`

Microsoft Azure public cloud IPv4 ranges (10,360 CIDRs). Lazy-loaded on first access.

### `get_fastly_ip_ranges() -> tuple[str, ...]`

Fastly CDN public IPv4 ranges (19 CIDRs). OpenAI uses Fastly as their edge CDN. Lazy-loaded.

### `get_anthropic_ip_ranges() -> tuple[str, ...]`

Anthropic (Claude) outbound IPv4 ranges. Used when Claude makes MCP tool calls to your server. Lazy-loaded.

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

With Railway deployment (requires `trusted_proxy_depth=3`):

```python
app.add_middleware(
    IpGuardMiddleware,
    protected_paths=["/mcp", "/mcp/messages"],
    trusted_proxy_depth=3,  # Railway: Fastly CDN + Railway proxy + app
)
```

## Usage with Python MCP Server

```python
from mcp.server.fastmcp import FastMCP
from mcp_ip_guard import create_ip_guard

guard = create_ip_guard(
    debug=True,
    trusted_proxy_depth=3,  # Railway deployment
    on_blocked=lambda ip, path: print(f"Blocked {ip} on {path}"),
)

mcp = FastMCP("my-server")

# In your custom HTTP handler or middleware:
client_ip = guard.get_client_ip(request)
result = guard.check_request(client_ip, request.url.path)
if not result.allowed:
    return JSONResponse({"error": "Access denied"}, status_code=403)
```

## Reverse Proxy Configuration

The guard extracts the client IP from the `X-Forwarded-For` header using `trusted_proxy_depth` to select the correct entry. **Getting this value wrong means the guard checks the wrong IP** — either a proxy's IP (too shallow) or a spoofable client-supplied IP (too deep).

### How `trusted_proxy_depth` works

Each reverse proxy in the chain appends the connecting IP to `X-Forwarded-For`. The guard reads from the **right** side of the header, skipping `trusted_proxy_depth` entries from the end:

```
X-Forwarded-For: <client_ip>, <proxy1_ip>, <proxy2_ip>
                  depth=3 ──┘    depth=2 ──┘    depth=1 ──┘
```

### Common deployments

| Platform | Proxy chain | Depth | XFF example |
|---|---|---|---|
| **Railway** | Client → Fastly CDN → Railway proxy → App | **3** | `52.173.123.5, 140.248.67.158, 167.82.233.39` |
| **Cloudflare only** | Client → Cloudflare → App | **2** | `52.173.123.5, 172.70.x.x` |
| **Single LB** | Client → Load Balancer → App | **2** | `52.173.123.5, 10.0.0.1` |
| **Direct** | Client → App | **1** | `52.173.123.5` |

### Railway example

Railway routes all traffic through Fastly CDN and its own internal proxy, producing **3 hops**. With the default `trusted_proxy_depth=1`, the guard would see Railway's proxy IP — not the actual caller:

```python
# WRONG — checks Railway's internal proxy IP
guard = create_ip_guard()

# CORRECT — skips Railway proxy + Fastly CDN to reach the real caller
guard = create_ip_guard(trusted_proxy_depth=3)
```

### How to find the right depth

Add a temporary debug endpoint to inspect the raw headers:

```python
@app.route("/debug/ip")
async def debug_ip(request):
    xff = request.headers.get("x-forwarded-for")
    client_ip = guard.get_client_ip(request)
    return JSONResponse({"xff": xff, "clientIp": client_ip})
```

Then `curl https://your-app.example.com/debug/ip` and count the entries in `xff`. The real client IP is the leftmost entry; set `trusted_proxy_depth` to the total number of entries to reach it. **Remove this endpoint before going to production.**

## ChatGPT Developer Mode

When connecting an MCP server directly to ChatGPT in developer mode, requests may come from Azure infrastructure IPs or Fastly CDN IPs rather than the dedicated OpenAI egress IPs:

```python
guard = create_ip_guard(
    include_azure_ranges=True,   # Azure infrastructure IPs (~10,360 ranges)
    include_fastly_ranges=True,  # Fastly CDN edge IPs (19 ranges)
)
```

Only enable these when you need developer-mode compatibility — in production with ChatGPT's public integration, the default OpenAI ranges are sufficient.

## Claude (Anthropic) MCP Tool Calls

When Claude makes MCP tool calls to your server, requests come from Anthropic's outbound IP range:

```python
guard = create_ip_guard(include_anthropic_ranges=True)
```

To allow both ChatGPT and Claude:

```python
guard = create_ip_guard(
    include_openai_ranges=True,      # ChatGPT (default)
    include_anthropic_ranges=True,   # Claude
    trusted_proxy_depth=3,           # Railway deployment
)
```

## Environment

- `ENVIRONMENT` (or `NODE_ENV` as fallback) — When set to `"production"`, localhost is blocked (unless `allow_localhost_in_dev=False`).

## IP Ranges Sources

- **OpenAI** — Published egress IPs (2026-03-03). Includes /28, /26, and /32 entries covering all ChatGPT outbound traffic to MCP servers.
- **Azure** — Microsoft Azure Service Tags – Public Cloud (2026-03-02). The `AzureCloud` service tag with 10,360 IPv4 CIDR ranges covering all Azure datacenter egress.
- **Fastly** — Fastly CDN public IP list (2026-03-04). 19 IPv4 ranges covering all Fastly edge nodes.
- **Anthropic** — Published outbound IPs (2026-03-04). The `160.79.104.0/21` range used for Claude MCP tool calls.

## License

MIT

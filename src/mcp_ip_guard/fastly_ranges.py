"""
Fastly CDN public IP ranges (IPv4 only).
Source: https://api.fastly.com/public-ip-list (2026-03-04)

OpenAI uses Fastly as their edge CDN. In ChatGPT developer mode,
requests to MCP servers may arrive from Fastly edge IPs rather than
the dedicated OpenAI egress ranges.

Total ranges: 19
"""

FASTLY_IP_RANGES: tuple[str, ...] = (
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "146.75.0.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
)

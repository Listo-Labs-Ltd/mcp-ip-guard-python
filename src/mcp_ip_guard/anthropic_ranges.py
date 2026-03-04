"""
Anthropic (Claude) IP ranges.
Source: https://docs.anthropic.com/en/docs/resources/ip-addresses (2026-03-04)

When Claude makes MCP tool calls to external servers, requests originate
from these outbound IP addresses.

Total ranges: 1 (outbound IPv4)
"""

ANTHROPIC_IP_RANGES: tuple[str, ...] = ("160.79.104.0/21",)

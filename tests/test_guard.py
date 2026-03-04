import pytest

from mcp_ip_guard.guard import IpGuard, create_ip_guard


class TestIsAllowed:
    def test_allows_openai_28_range(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        # 52.173.123.0/28 -> .0 through .15
        assert guard.is_allowed("52.173.123.5") is True
        assert guard.is_allowed("52.173.123.15") is True

    def test_blocks_outside_openai_ranges(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("8.8.8.8") is False

    def test_allows_openai_32_single_ip(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("130.33.24.99") is True

    def test_rejects_one_off_from_32(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("130.33.24.100") is False

    def test_allows_openai_26_range(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        # 12.129.184.64/26 -> .64 through .127
        assert guard.is_allowed("12.129.184.100") is True

    def test_handles_ipv6_mapped_ipv4(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("::ffff:52.173.123.5") is True
        assert guard.is_allowed("::ffff:8.8.8.8") is False

    def test_handles_ipv6_mapped_ipv4_uppercase(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("::FFFF:52.173.123.5") is True
        assert guard.is_allowed("::FFFF:8.8.8.8") is False

    def test_denies_pure_ipv6(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("2001:db8::1") is False

    def test_denies_invalid_formats(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("not-an-ip") is False
        assert guard.is_allowed("") is False

    def test_strips_whitespace(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed(" 52.173.123.5 ") is True
        assert guard.is_allowed(" 8.8.8.8 ") is False

    def test_allows_additional_custom_ranges(self) -> None:
        guard = create_ip_guard(
            additional_ranges=["10.0.0.0/8"],
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("10.1.2.3") is True
        assert guard.is_allowed("10.255.255.255") is True

    def test_allows_single_ip_without_prefix(self) -> None:
        guard = create_ip_guard(
            additional_ranges=["192.168.1.100"],
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("192.168.1.100") is True
        assert guard.is_allowed("192.168.1.101") is False

    def test_can_disable_openai_ranges(self) -> None:
        guard = create_ip_guard(
            include_openai_ranges=False,
            additional_ranges=["10.0.0.0/8"],
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("52.173.123.5") is False
        assert guard.is_allowed("10.1.2.3") is True


class TestAzureRanges:
    def test_not_included_by_default(self) -> None:
        guard = create_ip_guard(
            include_openai_ranges=False,
            allow_localhost_in_dev=False,
        )
        # 4.144.0.0/17 is an Azure range
        assert guard.is_allowed("4.144.0.1") is False

    def test_allows_azure_ips_when_enabled(self) -> None:
        guard = create_ip_guard(
            include_azure_ranges=True,
            allow_localhost_in_dev=False,
        )
        # 4.144.0.0/17 covers 4.144.0.0 - 4.144.127.255
        assert guard.is_allowed("4.144.0.1") is True
        assert guard.is_allowed("4.144.64.10") is True

    def test_adds_on_top_of_openai(self) -> None:
        guard = create_ip_guard(
            include_azure_ranges=True,
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("52.173.123.5") is True  # OpenAI
        assert guard.is_allowed("4.144.0.1") is True  # Azure

    def test_increases_range_count(self) -> None:
        base = create_ip_guard()
        with_azure = create_ip_guard(include_azure_ranges=True)
        assert with_azure.range_count > base.range_count + 5000


class TestAnthropicRanges:
    def test_not_included_by_default(self) -> None:
        guard = create_ip_guard(
            include_openai_ranges=False,
            allow_localhost_in_dev=False,
        )
        # 160.79.104.0/21 covers 160.79.104.0 - 160.79.111.255
        assert guard.is_allowed("160.79.106.42") is False

    def test_allows_anthropic_ips_when_enabled(self) -> None:
        guard = create_ip_guard(
            include_anthropic_ranges=True,
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("160.79.104.1") is True
        assert guard.is_allowed("160.79.111.254") is True

    def test_adds_on_top_of_openai(self) -> None:
        guard = create_ip_guard(
            include_anthropic_ranges=True,
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("52.173.123.5") is True  # OpenAI
        assert guard.is_allowed("160.79.106.42") is True  # Anthropic

    def test_increases_range_count(self) -> None:
        base = create_ip_guard()
        with_anthropic = create_ip_guard(include_anthropic_ranges=True)
        assert with_anthropic.range_count == base.range_count + 1


class TestFastlyRanges:
    def test_not_included_by_default(self) -> None:
        guard = create_ip_guard(
            include_openai_ranges=False,
            allow_localhost_in_dev=False,
        )
        # 140.248.67.158 is a Fastly IP — should be blocked without the flag
        assert guard.is_allowed("140.248.67.158") is False

    def test_allows_fastly_ips_when_enabled(self) -> None:
        guard = create_ip_guard(
            include_fastly_ranges=True,
            allow_localhost_in_dev=False,
        )
        # 140.248.64.0/18 covers 140.248.64.0 - 140.248.127.255
        assert guard.is_allowed("140.248.67.158") is True
        assert guard.is_allowed("140.248.67.124") is True

    def test_adds_on_top_of_openai(self) -> None:
        guard = create_ip_guard(
            include_fastly_ranges=True,
            allow_localhost_in_dev=False,
        )
        assert guard.is_allowed("52.173.123.5") is True  # OpenAI
        assert guard.is_allowed("140.248.67.158") is True  # Fastly

    def test_increases_range_count(self) -> None:
        base = create_ip_guard()
        with_fastly = create_ip_guard(include_fastly_ranges=True)
        assert with_fastly.range_count == base.range_count + 19


class TestLocalhostHandling:
    def test_allows_localhost_in_non_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "development")
        guard = create_ip_guard()
        assert guard.is_allowed("127.0.0.1") is True
        assert guard.is_allowed("::1") is True

    def test_blocks_localhost_in_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "production")
        guard = create_ip_guard()
        assert guard.is_allowed("127.0.0.1") is False
        assert guard.is_allowed("::1") is False

    def test_blocks_localhost_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "development")
        guard = create_ip_guard(allow_localhost_in_dev=False)
        assert guard.is_allowed("127.0.0.1") is False

    def test_respects_node_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        monkeypatch.setenv("NODE_ENV", "production")
        guard = create_ip_guard()
        assert guard.is_allowed("127.0.0.1") is False

    def test_localhost_string_is_not_bypassed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The literal string 'localhost' should NOT be in the bypass set."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        guard = create_ip_guard()
        assert guard.is_allowed("localhost") is False

    def test_production_check_evaluated_at_init(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_is_production() is captured at init, not re-evaluated per request."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        guard = create_ip_guard()
        # Changing env after init should NOT affect the guard
        monkeypatch.setenv("ENVIRONMENT", "production")
        assert guard.is_allowed("127.0.0.1") is True  # still uses init-time value


class TestGetClientIp:
    def test_uses_rightmost_xff(self) -> None:
        ip = IpGuard.get_client_ip_from_headers("10.0.0.1", "1.1.1.1, 2.2.2.2, 3.3.3.3")
        assert ip == "3.3.3.3"

    def test_falls_back_to_remote_addr(self) -> None:
        ip = IpGuard.get_client_ip_from_headers("10.0.0.1", None)
        assert ip == "10.0.0.1"

    def test_returns_unknown_when_no_info(self) -> None:
        ip = IpGuard.get_client_ip_from_headers(None, None)
        assert ip == "unknown"

    def test_extracts_from_asgi_scope(self) -> None:
        guard = create_ip_guard()
        scope = {
            "type": "http",
            "client": ("10.0.0.1", 12345),
            "headers": [
                (b"x-forwarded-for", b"1.1.1.1, 3.3.3.3"),
            ],
        }
        assert guard.get_client_ip(scope) == "3.3.3.3"

    def test_extracts_without_xff(self) -> None:
        guard = create_ip_guard()
        scope = {
            "type": "http",
            "client": ("10.0.0.1", 12345),
            "headers": [],
        }
        assert guard.get_client_ip(scope) == "10.0.0.1"

    def test_trusted_proxy_depth_2(self) -> None:
        """With depth=2, picks XFF[-2] to skip the inner proxy."""
        ip = IpGuard.get_client_ip_from_headers(
            "10.0.0.1", "client_ip, cdn_ip, lb_ip", trusted_proxy_depth=2
        )
        assert ip == "cdn_ip"

    def test_trusted_proxy_depth_clamps_to_list_length(self) -> None:
        """If depth exceeds XFF entries, use the leftmost (first) entry."""
        ip = IpGuard.get_client_ip_from_headers("10.0.0.1", "only_one_ip", trusted_proxy_depth=5)
        assert ip == "only_one_ip"

    def test_trusted_proxy_depth_via_guard(self) -> None:
        """trusted_proxy_depth is passed through to get_client_ip."""
        guard = create_ip_guard(trusted_proxy_depth=2)
        scope = {
            "type": "http",
            "client": ("10.0.0.1", 12345),
            "headers": [
                (b"x-forwarded-for", b"real_client, proxy1, proxy2"),
            ],
        }
        assert guard.get_client_ip(scope) == "proxy1"


class TestCheckRequest:
    def test_returns_allowed_for_openai_ip(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        result = guard.check_request("52.173.123.5", "/mcp")
        assert result.allowed is True
        assert result.client_ip == "52.173.123.5"

    def test_returns_blocked_for_unknown_ip(self) -> None:
        guard = create_ip_guard(allow_localhost_in_dev=False)
        result = guard.check_request("8.8.8.8", "/mcp")
        assert result.allowed is False

    def test_calls_on_blocked(self) -> None:
        blocked: list[tuple[str, str]] = []
        guard = create_ip_guard(
            allow_localhost_in_dev=False,
            on_blocked=lambda ip, path: blocked.append((ip, path)),
        )
        guard.check_request("8.8.8.8", "/mcp")
        assert blocked == [("8.8.8.8", "/mcp")]

    def test_on_blocked_exception_does_not_propagate(self) -> None:
        """A crashing on_blocked callback should not prevent the 403."""

        def bad_callback(ip: str, path: str) -> None:
            raise RuntimeError("callback crash")

        guard = create_ip_guard(
            allow_localhost_in_dev=False,
            on_blocked=bad_callback,
        )
        result = guard.check_request("8.8.8.8", "/mcp")
        assert result.allowed is False
        assert result.client_ip == "8.8.8.8"


class TestRangeCount:
    def test_reports_openai_ranges(self) -> None:
        guard = create_ip_guard()
        assert guard.range_count > 100

    def test_includes_additional_ranges(self) -> None:
        base = create_ip_guard()
        extended = create_ip_guard(additional_ranges=["10.0.0.0/8", "172.16.0.0/12"])
        assert extended.range_count == base.range_count + 2

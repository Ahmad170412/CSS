from dataclasses import dataclass, field
import re
from urllib.parse import urlparse


IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
# IPv6: bracketed [address]:port or unbracketed address (no port ambiguity)
# For unbracketed, we don't support port to avoid ambiguity with IPv6 address ending in digits
IPV6_BRACKETED = re.compile(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$")
IPV6_UNBRACKETED = re.compile(r"^([0-9a-fA-F:]+)$")
URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


def _parse_ipv6(address: str) -> tuple[str, str | None]:
    # Try bracketed format first: [::1]:8080
    match = IPV6_BRACKETED.match(address)
    if match:
        return match.group(1), match.group(2)
    # Unbracketed: ::1 (no port support to avoid ambiguity)
    match = IPV6_UNBRACKETED.match(address)
    if match:
        return match.group(1), None
    return "", None


def _parse_host_port(value: str) -> tuple[str, str | None]:
    if value.startswith("["):
        return _parse_ipv6(value)
    # Handle host:port for IPv4 and domain names (not IPv6)
    if ":" in value and not value.startswith("http"):
        # Check for bare IPv6 (unbracketed) before splitting
        # IPv6 without brackets: ::1, 2001:db8::1, etc.
        if _looks_like_ipv6(value):
            raise ValueError(
                f"Bare IPv6 address '{value}' not supported. Use bracketed format: [::1] or [::1]:8080"
            )
        parts = value.rsplit(":", 1)
        host = parts[0]
        port = parts[1]
        # Validate port is numeric and host is not IPv6 (which would be bracketed)
        if port.isdigit() and not _looks_like_ipv6(host):
            return host, port
    return value, None


def _looks_like_ipv6(address: str) -> bool:
    return address.count(":") >= 2


@dataclass
class Config:
    model: str = "llama3.2:3b"
    ollama_host: str = "http://localhost:11434"
    temperature: float = 0.1
    max_tokens: int = 4096
    scout_max_rounds: int = 10
    planner_max_rounds: int = 8
    raider_max_rounds: int = 8
    tool_timeout: int = 120
    max_workers: int = 4
    verify_ssl: bool = False
    verbose: bool = False
    skip_raider: bool = False
    proxy: str = ""
    tor: bool = False
    proxy_dns: bool = False

    def __post_init__(self):
        if self.tor and not self.proxy:
            self.proxy = "socks5://127.0.0.1:9050"

    def proxy_env(self) -> dict[str, str]:
        if not self.proxy:
            return {}
        from urllib.parse import urlparse
        no_proxy = {"localhost", "127.0.0.1", "::1"}
        # Parse ollama_host robustly (handle with or without scheme)
        ollama_host = self.ollama_host
        if not ollama_host.startswith(("http://", "https://")):
            ollama_host = "http://" + ollama_host
        parsed = urlparse(ollama_host)
        if parsed.hostname:
            no_proxy.add(parsed.hostname)
        env = {
            "HTTP_PROXY": self.proxy,
            "HTTPS_PROXY": self.proxy,
            "ALL_PROXY": self.proxy,
        }
        if not self.proxy_dns:
            env["NO_PROXY"] = ",".join(sorted(no_proxy))
        return env


@dataclass
class Target:
    original: str
    domain: str = ""
    ip: str = ""
    port: str | None = None
    is_url: bool = False
    is_ip: bool = False

    def __post_init__(self):
        self.is_url = bool(URL_PATTERN.match(self.original))

        if self.is_url:
            parsed = urlparse(self.original)
            self.domain = parsed.hostname or self.original
            self.port = str(parsed.port) if parsed.port else None
            self.is_ip = bool(IPV4_PATTERN.match(self.domain) or self._is_ipv6(self.domain))
            if self.is_ip:
                self.ip = self.domain
        else:
            try:
                host, port = _parse_host_port(self.original)
            except ValueError as e:
                raise ValueError(f"Invalid target format: {e}")
            self.port = port
            self.domain = host
            self.is_ip = bool(IPV4_PATTERN.match(host) or self._is_ipv6(host))
            if self.is_ip:
                self.ip = host

    def _is_ipv6(self, address: str) -> bool:
        if address.startswith("["):
            address = address[1:-1]
        # Check if it matches IPv6 pattern
        if not IPV6_UNBRACKETED.match(address):
            return False
        # Must contain at least one colon
        if ":" not in address:
            return False
        # Allow IPv4-mapped IPv6 (::ffff:192.168.1.1)
        parts = address.split(":")
        # Check each segment
        for part in parts:
            if part == "":
                continue  # Empty part from :: compression
            if "." in part:
                # IPv4-mapped segment - validate as IPv4
                if IPV4_PATTERN.match(part):
                    continue
                return False
            if not re.match(r"^[0-9a-fA-F]{1,4}$", part):
                return False
        return True

    def target_for_tools(self) -> str:
        if self.port:
            # For IPv6, tools expect bracketed format: [::1]:8080
            if self.is_ip and ":" in self.domain and not self.domain.startswith("["):
                return f"[{self.domain}]:{self.port}"
            return f"{self.domain}:{self.port}"
        return self.domain

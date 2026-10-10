"""Centralized Outbound URL Validation and SSRF Defense Mechanism.

Provides rigorous IP address filtering, DNS resolution validation, scheme enforcement,
and URL sanitization to protect backend network services against Server-Side Request
Forgery (SSRF), DNS rebinding, and unauthorized intranet access.
"""

import ipaddress
import logging
import socket
import urllib.parse
from typing import Any, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Explicitly allowed web schemes for outbound network inspection
ALLOWED_OUTBOUND_SCHEMES: Set[str] = {"http", "https"}

# Well-known restricted hostnames (direct loopback, container, and cloud metadata identifiers)
RESTRICTED_HOSTNAMES: Set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
}

# Maximum permitted redirect hops during manual redirect resolution
MAX_REDIRECT_HOPS: int = 3

# Maximum permitted response payload size (2 MB)
MAX_RESPONSE_BYTES: int = 2 * 1024 * 1024

# Default fetch timeout in seconds
DEFAULT_FETCH_TIMEOUT: float = 8.0

# Explicit restricted CIDR networks for defense-in-depth verification
RESTRICTED_IPV4_NETWORKS = [
    ipaddress.IPv4Network("0.0.0.0/8"),          # Current network (only valid as source address)
    ipaddress.IPv4Network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.IPv4Network("100.64.0.0/10"),      # RFC 6598 Shared Address Space (Carrier-grade NAT)
    ipaddress.IPv4Network("127.0.0.0/8"),        # RFC 1122 Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),     # RFC 3927 Link-Local / Cloud Instance Metadata
    ipaddress.IPv4Network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.IPv4Network("192.0.0.0/24"),       # RFC 6890 IETF Protocol Assignments
    ipaddress.IPv4Network("192.0.2.0/24"),       # RFC 5737 Documentation (TEST-NET-1)
    ipaddress.IPv4Network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.IPv4Network("198.18.0.0/15"),      # RFC 2544 Benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),    # RFC 5737 Documentation (TEST-NET-2)
    ipaddress.IPv4Network("203.0.113.0/24"),     # RFC 5737 Documentation (TEST-NET-3)
    ipaddress.IPv4Network("224.0.0.0/4"),        # RFC 5771 Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),        # RFC 1112 Reserved for Future Use
    ipaddress.IPv4Network("255.255.255.255/32"), # RFC 919 Limited Broadcast
]

RESTRICTED_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::/128"),             # Unspecified address
    ipaddress.IPv6Network("::1/128"),           # Loopback address
    ipaddress.IPv6Network("::ffff:0:0/96"),     # IPv4-mapped IPv6 (re-checked as embedded IPv4)
    ipaddress.IPv6Network("64:ff9b::/96"),      # IPv4/IPv6 translation
    ipaddress.IPv6Network("100::/64"),          # Discard prefix
    ipaddress.IPv6Network("2001:db8::/32"),     # Documentation
    ipaddress.IPv6Network("2002::/16"),         # 6to4 prefix (re-checked as embedded IPv4)
    ipaddress.IPv6Network("fc00::/7"),          # Unique Local Address (ULA / Private)
    ipaddress.IPv6Network("fe80::/10"),         # Link-Local Unicast
    ipaddress.IPv6Network("ff00::/8"),          # Multicast
]


class SSRFSecurityError(ValueError):
    """Exception raised when an outbound network request is blocked by SSRF validation guards."""
    pass


def is_ip_restricted(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> Tuple[bool, Optional[str]]:
    """Determine whether an IP address belongs to a non-public, internal, or restricted range.

    Handles IPv4, IPv6, IPv4-mapped IPv6 (::ffff:x.x.x.x), and 6to4 encapsulation.

    Args:
        ip_obj: An IPv4Address or IPv6Address instance.

    Returns:
        Tuple of (is_restricted: bool, rejection_reason: Optional[str]).
    """
    # 1. Inspect IPv6 edge cases and mapped encodings
    if isinstance(ip_obj, ipaddress.IPv6Address):
        # Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
        if ip_obj.ipv4_mapped:
            return is_ip_restricted(ip_obj.ipv4_mapped)

        # Handle 6to4 prefix (2002::/16) where bytes 2-5 contain the embedded IPv4
        if ip_obj in ipaddress.IPv6Network("2002::/16"):
            embedded_v4 = ipaddress.IPv4Address(ip_obj.packed[2:6])
            return is_ip_restricted(embedded_v4)

        # Check explicit IPv6 restricted networks
        for net in RESTRICTED_IPV6_NETWORKS:
            if ip_obj in net:
                return True, "SSRF Guard: Restricted IPv6 destination blocked."

    # 2. Inspect IPv4 explicit restricted networks
    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net in RESTRICTED_IPV4_NETWORKS:
            if ip_obj in net:
                return True, "SSRF Guard: Restricted IPv4 destination blocked."

    # 3. Standard library general property checks
    if (
        not ip_obj.is_global
        or ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True, "SSRF Guard: Non-global or private destination blocked."

    return False, None


def resolve_and_validate_hostname(hostname: str) -> Tuple[bool, List[str], Optional[str]]:
    """Resolve all DNS answers for a hostname and verify that every destination IP is public.

    Rejects requests if ANY returned IP belongs to loopback, private, link-local,
    or cloud metadata address spaces.

    Args:
        hostname: Domain name or literal IP address string.

    Returns:
        Tuple of (is_safe: bool, resolved_ips: List[str], error_message: Optional[str]).
    """
    if not hostname:
        return False, [], "Empty hostname provided."

    clean_host = hostname.strip().lower().rstrip(".")

    # Direct check for restricted hostnames
    if clean_host in RESTRICTED_HOSTNAMES:
        return False, [], "SSRF Guard: Direct loopback destination blocked."

    # Check if host is a literal IP address
    clean_ip_str = clean_host.strip("[]")
    try:
        literal_ip = ipaddress.ip_address(clean_ip_str)
        is_restr, reason = is_ip_restricted(literal_ip)
        if is_restr:
            return False, [], reason
        return True, [clean_ip_str], None
    except ValueError:
        pass  # Host is a domain name, proceed to DNS resolution

    try:
        # Resolve all IPv4 and IPv6 addresses for the hostname
        addr_info = socket.getaddrinfo(
            clean_host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

        if not addr_info:
            return False, [], "DNS resolution failed: Host returned no address records."

        resolved_ips: List[str] = []
        for item in addr_info:
            ip_str = item[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

            ip_obj = ipaddress.ip_address(ip_str)
            is_restr, reason = is_ip_restricted(ip_obj)
            if is_restr:
                return False, [], "SSRF Guard: Target host resolves to restricted destination."

        return True, resolved_ips, None

    except socket.gaierror:
        # Host could not be resolved; allow HTTP client to handle DNS/connection error gracefully
        return True, [], None
    except Exception as exc:
        logger.warning("Unexpected error during SSRF DNS resolution for '%s': %s", clean_host, exc)
        return False, [], "SSRF validation encountered a network resolution error."


def is_safe_ssrf_destination(hostname: str) -> Tuple[bool, Optional[str]]:
    """Legacy compatibility wrapper verifying whether a target hostname is safe to query.

    Args:
        hostname: Domain name or IP string.

    Returns:
        Tuple of (is_safe: bool, error_reason: Optional[str]).
    """
    ok, _, err = resolve_and_validate_hostname(hostname)
    return ok, err


def validate_outbound_url(
    raw_url: str,
) -> Tuple[bool, Optional[str]]:
    """Perform strict structural and destination validation on an outbound URL before making network calls.

    Ensures the scheme is strictly HTTP or HTTPS, disallows embedded credentials,
    validates port numbers, and verifies destination IP addresses against SSRF restrictions.

    Args:
        raw_url: Raw URL string intended for HTTP fetching.

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str]).
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return False, "Outbound URL cannot be empty."

    url_str = raw_url.strip()

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception as exc:
        return False, f"Malformed URL could not be parsed: {exc}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_OUTBOUND_SCHEMES:
        return False, f"Unsupported scheme '{scheme}': Outbound fetcher only permits HTTP and HTTPS."

    # Disallow embedded userinfo / credentials in target fetch URL (e.g. http://user:pass@host)
    if parsed.username is not None or parsed.password is not None:
        return False, "Outbound fetching prohibits embedded credentials in target URL."

    hostname = parsed.hostname
    if not hostname or len(hostname.strip()) == 0:
        return False, "Target URL lacks a valid hostname."

    # Validate port range if explicitly specified
    try:
        if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
            return False, f"Invalid port number: {parsed.port}"
    except ValueError:
        return False, "Malformed port in target URL."

    # Verify destination IP addresses against SSRF restrictions
    is_safe_host, _, dns_err = resolve_and_validate_hostname(hostname)
    if not is_safe_host:
        return False, dns_err or "Target destination is restricted."

    return True, None


def sanitize_url_for_logging(raw_url: Optional[str]) -> str:
    """Sanitize URL for logs and error responses by stripping credentials and redacting sensitive query parameters.

    Args:
        raw_url: Raw input URL string.

    Returns:
        Clean sanitized URL string with sensitive tokens masked.
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    try:
        parsed = urllib.parse.urlsplit(raw_url)

        # Strip userinfo credentials from netloc
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[-1]

        # Redact sensitive authentication/session query parameters
        if parsed.query:
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            sensitive_keys = {
                "token", "password", "pwd", "pass", "secret", "auth",
                "key", "api_key", "apikey", "access_token", "refresh_token",
                "session", "session_id", "sessionid", "code", "pin", "ssn",
                "credit_card", "card", "cvv", "sig", "signature", "jwt",
            }
            sanitized_pairs = []
            for k, v in query_pairs:
                if k.lower() in sensitive_keys:
                    sanitized_pairs.append((k, "[REDACTED]"))
                else:
                    sanitized_pairs.append((k, v))
            clean_query = urllib.parse.urlencode(sanitized_pairs, safe="[]")
        else:
            clean_query = ""

        # Reassemble URL
        clean_url = urllib.parse.urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            clean_query,
            parsed.fragment,
        ))
        return clean_url
    except Exception:
        return "[SANITIZATION_ERROR]"


def resolve_and_validate_all_ips(
    hostname: str,
    port: int = 80,
) -> Tuple[bool, List[str], Optional[str]]:
    """Resolve DNS records for a target hostname and verify that every destination IP is public.

    Handles IPv4 and IPv6 addresses. If ANY address record resolves to loopback, private,
    link-local, cloud metadata, or restricted CIDR ranges, the destination is rejected.

    Args:
        hostname: Domain name or literal IP address string.
        port: Destination port number.

    Returns:
        Tuple of (is_safe: bool, validated_ips: List[str], error_message: Optional[str]).
    """
    if not hostname:
        return False, [], "SSRF Guard: Empty hostname provided."

    clean_host = hostname.strip().lower().rstrip(".")
    if clean_host in RESTRICTED_HOSTNAMES:
        return False, [], "SSRF Guard: Direct loopback destination blocked."

    clean_ip_str = clean_host.strip("[]")
    try:
        literal_ip = ipaddress.ip_address(clean_ip_str)
        is_restr, reason = is_ip_restricted(literal_ip)
        if is_restr:
            return False, [], reason
        return True, [clean_ip_str], None
    except ValueError:
        pass  # Domain name; proceed to DNS lookup

    try:
        addr_info = socket.getaddrinfo(
            clean_host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        if not addr_info:
            return False, [], f"SSRF Guard: DNS resolution returned no address records for '{clean_host}'."

        validated_ips: List[str] = []
        for item in addr_info:
            ip_str = item[4][0]
            if ip_str not in validated_ips:
                validated_ips.append(ip_str)

            ip_obj = ipaddress.ip_address(ip_str)
            is_restr, reason = is_ip_restricted(ip_obj)
            if is_restr:
                return False, [], f"SSRF Guard: Host '{clean_host}' resolves to restricted destination ({ip_str})."

        return True, validated_ips, None

    except socket.gaierror as gai_err:
        return False, [], f"DNS resolution failed: {gai_err}"
    except Exception as exc:
        logger.warning("SSRF DNS verification error for '%s': %s", clean_host, exc)
        return False, [], f"SSRF DNS verification error: {exc}"


# =============================================================================
# Connection-Pinning Transports & Adapters (DNS Rebinding Immunity)
# =============================================================================

import anyio
import httpcore
from httpcore._backends.anyio import AnyIOBackend, AnyIOStream
from httpcore._exceptions import ConnectError as HttpcoreConnectError, ConnectTimeout as HttpcoreConnectTimeout, map_exceptions
import httpx
import requests.adapters
import urllib3.connection
import urllib3.util.connection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NameResolutionError, NewConnectionError


class SSRFGuardedNetworkBackend(AnyIOBackend):
    """Custom HTTPCore network backend that guarantees socket connection pinning to validated public IPs.

    Resolves DNS at socket connection time, validates every resolved address against SSRF rules,
    and directly connects the TCP socket to the validated numeric IP string.
    This eliminates TOCTOU DNS rebinding while preserving SNI and TLS certificate verification.
    """

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        safe, valid_ips, err = resolve_and_validate_all_ips(host, port)
        if not safe or not valid_ips:
            raise HttpcoreConnectError(f"SSRF Guard: Destination host '{host}' blocked: {err}")

        # Pin the TCP socket connection directly to the first validated public IP address
        pinned_ip = valid_ips[0]

        if socket_options is None:
            socket_options = []

        exc_map = {
            TimeoutError: HttpcoreConnectTimeout,
            OSError: HttpcoreConnectError,
            anyio.BrokenResourceError: HttpcoreConnectError,
        }

        with map_exceptions(exc_map):
            with anyio.fail_after(timeout):
                stream = await anyio.connect_tcp(
                    remote_host=pinned_ip,
                    remote_port=port,
                    local_host=local_address,
                )
                for option in socket_options:
                    stream._raw_socket.setsockopt(*option)

        return AnyIOStream(stream)


class SSRFGuardedAsyncTransport(httpx.AsyncHTTPTransport):
    """Async HTTP transport enforcing connection pinning and SSRF defense on all outbound requests."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self._pool._ssl_context,
            max_connections=10,
            network_backend=SSRFGuardedNetworkBackend(),
        )


class SSRFGuardedHTTPConnection(urllib3.connection.HTTPConnection):
    """Synchronous HTTP connection ensuring socket connect pins to validated public IP."""

    def _new_conn(self) -> socket.socket:
        safe, valid_ips, err = resolve_and_validate_all_ips(self._dns_host, self.port)
        if not safe or not valid_ips:
            raise NewConnectionError(self, f"SSRF Guard: Target host '{self.host}' blocked: {err}")

        pinned_ip = valid_ips[0]
        return urllib3.util.connection.create_connection(
            (pinned_ip, self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )


class SSRFGuardedHTTPSConnection(urllib3.connection.HTTPSConnection):
    """Synchronous HTTPS connection ensuring socket connect pins to validated public IP while preserving TLS SNI."""

    def _new_conn(self) -> socket.socket:
        safe, valid_ips, err = resolve_and_validate_all_ips(self._dns_host, self.port)
        if not safe or not valid_ips:
            raise NewConnectionError(self, f"SSRF Guard: Target host '{self.host}' blocked: {err}")

        pinned_ip = valid_ips[0]
        return urllib3.util.connection.create_connection(
            (pinned_ip, self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )


class SSRFGuardedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = SSRFGuardedHTTPConnection


class SSRFGuardedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = SSRFGuardedHTTPSConnection


class SSRFGuardedSyncAdapter(requests.adapters.HTTPAdapter):
    """Synchronous requests adapter using SSRF-guarded and connection-pinned connection pools."""

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": SSRFGuardedHTTPConnectionPool,
            "https": SSRFGuardedHTTPSConnectionPool,
        }


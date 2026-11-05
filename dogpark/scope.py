"""Scope lock — the one gate every target must pass before a command can be built or run.

Pure stdlib, no GUI imports, no network calls at import time. `Scope.check()` does a DNS
lookup via `socket.getaddrinfo`, which is the only network-ish thing this module ever does,
and only when explicitly called (never at import).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional, Union

IPAddr = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Always-reject ranges, regardless of what the allowlist says. These are the classic
# "looks private but isn't ours" traps: link-local APIPA and the cloud metadata address.
ALWAYS_REJECT: tuple[IPNet, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 link-local / APIPA (incl. 169.254.169.254 metadata)
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
)

# Default allowlist per the DOGPARK playbook: RFC1918 + loopback, v4 and v6.
DEFAULT_ALLOWED_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]


@dataclass(frozen=True)
class ScopeResult:
    ok: bool
    target: str
    ip: Optional[str]
    reason: str


class Scope:
    """Validates a target (hostname or IP) against the authorized-CIDR allowlist."""

    def __init__(self, allowed_cidrs=None, lab_subnet: Optional[str] = None, inventory=None):
        cidrs = list(allowed_cidrs) if allowed_cidrs else list(DEFAULT_ALLOWED_CIDRS)
        if lab_subnet:
            cidrs.append(lab_subnet)
        self.networks: list[IPNet] = []
        for c in cidrs:
            try:
                self.networks.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                # Skip malformed entries rather than crash the app over a bad config line.
                continue
        self.inventory = dict(inventory) if inventory else {}

    @classmethod
    def from_config(cls, config: dict) -> "Scope":
        return cls(
            allowed_cidrs=config.get("allowed_cidrs"),
            lab_subnet=config.get("lab_subnet"),
            inventory=config.get("inventory"),
        )

    def _resolve(self, target: str) -> Optional[str]:
        """Resolve a hostname or literal IP to a single IP string, or None if it won't resolve."""
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(target, None)
        except (socket.gaierror, socket.error, UnicodeError):
            return None
        if not infos:
            return None
        return infos[0][4][0]

    def _in_allowed_network(self, ip: IPAddr) -> bool:
        return any(ip in net for net in self.networks)

    def _always_rejected(self, ip: IPAddr) -> Optional[str]:
        for net in ALWAYS_REJECT:
            if ip.version == net.version and ip in net:
                if net == ipaddress.ip_network("169.254.0.0/16") and str(ip) == "169.254.169.254":
                    return "cloud metadata address (169.254.169.254) is always refused"
                return f"link-local/APIPA address ({net}) is always refused"
        return None

    def check(self, target: str) -> ScopeResult:
        """Resolve + validate a target. Never raises; always returns a ScopeResult."""
        if not target or not target.strip():
            return ScopeResult(False, target, None, "empty target")
        target = target.strip()

        ip_str = self._resolve(target)
        if ip_str is None:
            return ScopeResult(False, target, None, "could not resolve hostname — scope unclear, refusing")

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return ScopeResult(False, target, ip_str, "resolved address is not a valid IP — refusing")

        reject_reason = self._always_rejected(ip)
        if reject_reason:
            return ScopeResult(False, target, str(ip), reject_reason)

        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return ScopeResult(False, target, str(ip), "multicast/reserved/unspecified address — refusing")

        if not self._in_allowed_network(ip):
            if ip.is_global:
                return ScopeResult(False, target, str(ip), f"{ip} is a public IP — out of scope")
            return ScopeResult(False, target, str(ip), f"{ip} is outside the authorized lab CIDRs — out of scope")

        return ScopeResult(True, target, str(ip), f"IN SCOPE ({ip})")

import ipaddress
import socket
from pathlib import Path


class PathViolation(Exception):
    pass


class EgressViolation(Exception):
    pass


class PathPolicy:
    """Every requested path is resolved first, then checked against the roots.

    Resolving before comparing is what catches symlink escapes: a link inside an
    allowed root that points outside it must not be readable.
    """

    def __init__(self, roots: list[Path]) -> None:
        self.roots = [Path(root).resolve() for root in roots]

    def resolve(self, requested: str) -> Path:
        if not self.roots:
            raise PathViolation("no roots configured")

        candidate = Path(requested).expanduser().resolve()
        for root in self.roots:
            if candidate == root or root in candidate.parents:
                return candidate
        raise PathViolation(f"path outside allowed roots: {requested}")


class EgressPolicy:
    def __init__(self, allowlist: list[str]) -> None:
        self.allowlist = {host.lower() for host in allowlist}

    def check(self, host: str) -> None:
        if host.lower() not in self.allowlist:
            raise EgressViolation(f"host not allowlisted: {host}")

        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror as exc:
            raise EgressViolation(f"cannot resolve host: {host}") from exc

        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise EgressViolation(f"host resolves to a blocked range: {address}")

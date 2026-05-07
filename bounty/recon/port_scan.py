"""
bounty.recon.port_scan — Async port scanning via naabu.

naabu is run as a subprocess with ``asyncio.create_subprocess_exec``.
Results are parsed from naabu's ``-json`` output (one object per line).

Port sets:
  top100    — naabu built-in top-100 common ports
  top1000   — naabu built-in top-1000 ports
  web       — 80,443,8000-9000 (common web interface ports)
  admin     — admin panel ports per misconfig-corpus Cat 6

Rate limiting:
  The naabu ``-rate`` flag controls packets-per-second.  Values are
  intensity-aware:
    gentle     → 100 pps
    normal     → 1000 pps
    aggressive → 5000 pps

Concurrency:
  A module-level semaphore limits simultaneous naabu processes to prevent
  the local VM's network interface from being overwhelmed.  Default is 3
  concurrent scans.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass
from typing import ClassVar

from bounty import get_logger
from bounty.config import get_settings
from bounty.exceptions import ToolFailedError, ToolMissingError, ToolTimeoutError
from bounty.recon.subdomains import _find_tool  # reuse the binary locator

log = get_logger(__name__)

# Common web interface ports (used for the 'web' preset)
_WEB_PORTS = "80,443,8000,8001,8008,8080,8081,8082,8083,8088,8090,8443,8444,8888,9000,9001,9090,9200,9443"

# Common admin panel ports (misconfig-corpus Cat 6 + commonly exposed management)
_ADMIN_PORTS = (
    "80,443,2375,2376,3000,3306,5432,5601,6379,8080,8161,8443,8888,9000,"
    "9090,9100,9200,9243,9300,15672,27017,28017,50070,50075,50090,61616"
)

# Intensity → rate (packets/sec)
_RATE_MAP: dict[str, int] = {
    "gentle": 100,
    "normal": 1000,
    "aggressive": 5000,
}

# Scan timeout per target (seconds)
_SCAN_TIMEOUT = 300  # 5 minutes

# Max simultaneous naabu processes
_MAX_CONCURRENT_SCANS = 3
_scan_sem = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)


@dataclass
class OpenPort:
    """An open TCP port discovered on a host.

    Attributes:
        ip: Target IP address.
        port: TCP port number.
        protocol: ``"tcp"`` or ``"udp"`` (naabu is TCP-only currently).
        service_guess: Best-guess service name from naabu banner or IANA.
        banner: Raw banner text if captured.
    """

    ip: str
    port: int
    protocol: str = "tcp"
    service_guess: str = ""
    banner: str = ""


# Minimal IANA-inspired service name lookup for common ports
_IANA: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2375: "docker-http", 2376: "docker-https", 3000: "dev-http",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5601: "kibana",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8161: "activemq", 8443: "https-alt", 8888: "jupyter",
    9000: "php-fpm-or-sonarqube", 9090: "prometheus", 9100: "node-exporter",
    9200: "elasticsearch-http", 9300: "elasticsearch-transport",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 28017: "mongodb-http",
    50070: "hadoop-namenode", 61616: "activemq-broker",
}


def _port_set_to_naabu_arg(port_set: str) -> str:
    """Convert a port set name to a naabu ``-p`` argument.

    Args:
        port_set: One of ``"top100"``, ``"top1000"``, ``"web"``, ``"admin"``.

    Returns:
        Port specification string for naabu (e.g. ``"top-100"`` or explicit list).
    """
    if port_set == "top100":
        return "top-100"
    if port_set == "top1000":
        return "top-1000"
    if port_set == "web":
        return _WEB_PORTS
    if port_set == "admin":
        return _ADMIN_PORTS
    # Treat as a literal port list or individual port
    return port_set


async def scan_ports(
    ip: str,
    *,
    port_set: str = "top100",
    intensity: str = "normal",
) -> list[OpenPort]:
    """Run naabu against a single IP and return discovered open ports.

    Args:
        ip: Target IP address (IPv4 or IPv6).
        port_set: Pre-defined port group or explicit comma-separated ports.
        intensity: One of ``"gentle"``, ``"normal"``, ``"aggressive"``.

    Returns:
        List of ``OpenPort`` objects for each open port found.

    Raises:
        ToolMissingError: If naabu is not installed.
        ToolTimeoutError: If the scan exceeds ``_SCAN_TIMEOUT`` seconds.
        ToolFailedError: If naabu exits non-zero.
    """
    binary = _find_tool("naabu")
    rate = _RATE_MAP.get(intensity, 1000)
    ports_arg = _port_set_to_naabu_arg(port_set)

    cmd = [
        binary,
        "-host", ip,
        "-p", ports_arg,
        "-rate", str(rate),
        "-silent",
        "-json",
        "-no-color",
    ]

    bound_log = log.bind(ip=ip, port_set=port_set, intensity=intensity)
    bound_log.info("naabu_start")

    async with _scan_sem:
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            assert proc.stderr is not None

            open_ports: list[OpenPort] = []

            try:
                async with asyncio.timeout(_SCAN_TIMEOUT):
                    async for raw_line in proc.stdout:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        port = _parse_naabu_line(line, ip)
                        if port:
                            bound_log.debug(
                                "naabu_open_port",
                                port=port.port,
                                service=port.service_guess,
                            )
                            open_ports.append(port)
            except TimeoutError:
                if proc.returncode is None:
                    proc.kill()
                raise ToolTimeoutError("naabu", _SCAN_TIMEOUT)

            await proc.wait()
            stderr_raw = await proc.stderr.read()
            stderr_text = stderr_raw.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                raise ToolFailedError("naabu", proc.returncode, stderr_text[:500])

            bound_log.info("naabu_done", open_ports=len(open_ports))
            return open_ports

        except (ToolMissingError, ToolTimeoutError, ToolFailedError):
            raise
        except Exception as exc:  # noqa: BLE001
            bound_log.error("naabu_unexpected_error", error=str(exc))
            raise ToolFailedError("naabu", -1, str(exc)) from exc
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass


def _parse_naabu_line(line: str, fallback_ip: str) -> OpenPort | None:
    """Parse a single line from naabu's JSONL output.

    naabu ``-json`` emits objects like::

        {"ip": "93.184.216.34", "port": 443, "protocol": "tcp"}

    Args:
        line: One output line from naabu.
        fallback_ip: IP to use if the JSON doesn't contain one.

    Returns:
        An ``OpenPort`` or ``None`` if the line is unparseable.
    """
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            ip = str(obj.get("ip", fallback_ip)).strip()
            port_val = obj.get("port")
            if port_val is None:
                return None
            port_num = int(port_val)
            protocol = str(obj.get("protocol", "tcp")).lower()
            banner = str(obj.get("banner", "")).strip()
            service = _IANA.get(port_num, "")
            return OpenPort(
                ip=ip,
                port=port_num,
                protocol=protocol,
                service_guess=service,
                banner=banner,
            )
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
    # Sometimes naabu emits bare "ip:port" format
    if ":" in line:
        parts = line.rsplit(":", 1)
        if len(parts) == 2:
            try:
                port_num = int(parts[1])
                return OpenPort(
                    ip=parts[0],
                    port=port_num,
                    service_guess=_IANA.get(port_num, ""),
                )
            except ValueError:
                pass
    return None


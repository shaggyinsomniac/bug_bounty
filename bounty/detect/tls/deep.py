from __future__ import annotations
import asyncio
import ssl
import socket
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult, ProbeResult

__all__ = [
    "TlsWeakProtocols",
    "TlsWeakCiphers",
    "TlsCertExpired",
    "TlsCertSelfSigned",
    "TlsCertHostnameMismatch",
]

_CONNECT_TIMEOUT = 10.0


def _https_asset(asset: Asset) -> bool:
    return asset.scheme == "https" or asset.primary_scheme == "https"


def _get_port(asset: Asset) -> int:
    if asset.port:
        return asset.port
    return 443


def _fake_pr(asset: Asset, desc: str) -> ProbeResult:
    return ProbeResult(
        url=asset.url, final_url=asset.url,
        status_code=200, headers={},
        body=desc.encode(), body_text=desc,
    )


async def _tls_connect(
    host: str, port: int, ctx: ssl.SSLContext
) -> ssl.SSLSocket | None:
    loop = asyncio.get_event_loop()
    try:
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, _blocking_connect, host, port, ctx),
            timeout=_CONNECT_TIMEOUT,
        )
        return raw
    except Exception:  # noqa: BLE001
        return None


def _blocking_connect(host: str, port: int, ctx: ssl.SSLContext) -> ssl.SSLSocket:
    raw_sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT)
    wrapped = ctx.wrap_socket(raw_sock, server_hostname=host)
    return wrapped


class TlsWeakProtocols(Detection):
    id = "tls.weak_protocols"
    name = "TLS 1.0/1.1 Accepted"
    category = "tls_configuration"
    severity_default = 500
    cwe = "CWE-326"
    tags: tuple[str, ...] = ("tls", "weak-protocol")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _https_asset(asset)

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        host = asset.host
        port = _get_port(asset)
        for proto_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                ssl_ctx.minimum_version = proto_version
                ssl_ctx.maximum_version = proto_version
            except (AttributeError, ssl.SSLError):
                continue
            sock = await _tls_connect(host, port, ssl_ctx)
            if sock is not None:
                try:
                    ver = sock.version() or "TLS1.x"
                finally:
                    sock.close()
                pr = _fake_pr(asset, f"Weak TLS version accepted: {ver}")
                await ctx.capture_evidence(asset.url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}",
                    title=f"Weak TLS protocol ({ver}) accepted at {asset.host}",
                    category=self.category, severity=self.severity_default,
                    url=asset.url, path="",
                    description=f"Server accepted connection using deprecated {ver}.",
                    remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 minimum.",
                    cwe=self.cwe, tags=list(self.tags),
                )
                return


class TlsWeakCiphers(Detection):
    id = "tls.weak_ciphers"
    name = "Weak TLS Ciphers Accepted (RC4/DES/EXPORT)"
    category = "tls_configuration"
    severity_default = 600
    cwe = "CWE-326"
    tags: tuple[str, ...] = ("tls", "weak-cipher", "rc4")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _https_asset(asset)

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        host = asset.host
        port = _get_port(asset)
        weak_ciphers = "RC4:DES:EXPORT:IDEA:SEED:CAMELLIA"
        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.set_ciphers(weak_ciphers)
        except ssl.SSLError:
            return
        sock = await _tls_connect(host, port, ssl_ctx)
        if sock is not None:
            try:
                cipher = sock.cipher()
                cipher_name = cipher[0] if cipher else "unknown"
            finally:
                sock.close()
            pr = _fake_pr(asset, f"Weak cipher accepted: {cipher_name}")
            await ctx.capture_evidence(asset.url, pr)
            yield FindingDraft(
                asset_id=asset.id, scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}",
                title=f"Weak TLS cipher ({cipher_name}) accepted at {asset.host}",
                category=self.category, severity=self.severity_default,
                url=asset.url, path="",
                description=f"Server negotiated weak cipher: {cipher_name}.",
                remediation="Disable RC4, DES, EXPORT ciphers; use modern AEAD ciphers.",
                cwe=self.cwe, tags=list(self.tags),
            )


class TlsCertExpired(Detection):
    id = "tls.cert_expired"
    name = "TLS Certificate Expired"
    category = "tls_certificate"
    severity_default = 800
    cwe = "CWE-298"
    tags: tuple[str, ...] = ("tls", "certificate", "expired")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _https_asset(asset)

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        host = asset.host
        port = _get_port(asset)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        sock = await _tls_connect(host, port, ssl_ctx)
        if sock is None:
            return
        try:
            cert = sock.getpeercert()
        finally:
            sock.close()
        if not cert:
            return
        not_after_str = cert.get("notAfter", "")
        if not not_after_str:
            return
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return
        now = datetime.now(tz=timezone.utc)
        if not_after >= now:
            return
        pr = _fake_pr(asset, f"Expired TLS cert: not_after={not_after_str}")
        await ctx.capture_evidence(asset.url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"TLS certificate expired at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description=f"TLS certificate expired on {not_after_str}.",
            remediation="Renew the TLS certificate immediately.",
            cwe=self.cwe, tags=list(self.tags),
        )


class TlsCertSelfSigned(Detection):
    id = "tls.cert_self_signed"
    name = "TLS Certificate Self-Signed"
    category = "tls_certificate"
    severity_default = 400
    cwe = "CWE-295"
    tags: tuple[str, ...] = ("tls", "certificate", "self-signed")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _https_asset(asset)

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        host = asset.host
        port = _get_port(asset)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        sock = await _tls_connect(host, port, ssl_ctx)
        if sock is None:
            return
        try:
            cert = sock.getpeercert()
        finally:
            sock.close()
        if not cert:
            return
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject != issuer:
            return
        pr = _fake_pr(asset, "Self-signed TLS certificate")
        await ctx.capture_evidence(asset.url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Self-signed TLS certificate at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description="TLS certificate is self-signed (subject == issuer).",
            remediation="Replace with a certificate from a trusted CA.",
            cwe=self.cwe, tags=list(self.tags),
        )


class TlsCertHostnameMismatch(Detection):
    id = "tls.cert_hostname_mismatch"
    name = "TLS Certificate Hostname Mismatch"
    category = "tls_certificate"
    severity_default = 500
    cwe = "CWE-297"
    tags: tuple[str, ...] = ("tls", "certificate", "hostname-mismatch")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _https_asset(asset)

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        host = asset.host
        port = _get_port(asset)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        sock = await _tls_connect(host, port, ssl_ctx)
        if sock is None:
            return
        try:
            cert = sock.getpeercert()
        finally:
            sock.close()
        if not cert:
            return
        try:
            ssl.match_hostname(cert, host)  # type: ignore[attr-defined]
            return  # no mismatch
        except (ssl.CertificateError, AttributeError):
            pass
        # ssl.match_hostname may not exist in Python 3.12+ — verify manually
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if sans:
            for san in sans:
                try:
                    ssl.match_hostname({"subjectAltName": [("DNS", san)]}, host)  # type: ignore[attr-defined]
                    return
                except (ssl.CertificateError, AttributeError):
                    continue
        cn_tuples = [x[0] for x in cert.get("subject", []) if x[0][0] == "commonName"]
        cn = cn_tuples[0][1] if cn_tuples else None
        if cn and (cn == host or (cn.startswith("*.") and host.endswith(cn[1:]))):
            return
        pr = _fake_pr(asset, f"CN/SAN mismatch for host {host}")
        await ctx.capture_evidence(asset.url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"TLS cert hostname mismatch at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description=f"TLS certificate does not match hostname '{host}'.",
            remediation="Obtain a certificate valid for the correct hostname.",
            cwe=self.cwe, tags=list(self.tags),
        )

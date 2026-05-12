"""
bounty.detect.network_services.databases — Exposed database and cache service detections.

Five detections via raw TCP banner-grab:
- RedisExposed                — port 6379, PING→+PONG
- MongoExposed                — port 27017, MongoDB handshake present
- ElasticsearchHttpExposed    — port 9200, HTTP cluster info (no auth)
- PostgresExposed             — port 5432, PostgreSQL server greeting
- MysqlExposed                — port 3306, MySQL handshake banner
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect.admin_panels._common import parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult
from bounty.recon.banner_grab import grab_banner

# Redis PING probe
_REDIS_PING = b"PING\r\n"


class RedisExposed(Detection):
    """Redis server accessible without authentication on port 6379."""

    id = "network_services.redis.exposed"
    name = "Redis Server Exposed"
    category = "network_service_exposure"
    severity_default = 950
    cwe = "CWE-306"
    tags = ("redis", "database", "unauthenticated", "rce")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return asset.port == 6379

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        host = asset.ip or asset.host
        result = await grab_banner(host, 6379, probe=_REDIS_PING)
        if not result.connected:
            return
        banner = result.banner
        # Redis responds to PING with "+PONG\r\n" (no auth)
        if b"+PONG" not in banner and b"+OK" not in banner:
            # Also accept inline banner starting with "-ERR" if it's a Redis error
            # but +PONG is the definitive no-auth indicator
            return

        # Build a fake ProbeResult for evidence capture
        from bounty.models import ProbeResult
        fake_pr = ProbeResult(
            url=f"redis://{host}:6379",
            final_url=f"redis://{host}:6379",
            status_code=200,
            headers={},
            body=banner,
            body_text=banner.decode("utf-8", errors="replace"),
        )
        await ctx.capture_evidence(f"redis://{host}:6379", fake_pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Redis server exposed without auth at {asset.host}:6379",
            category=self.category,
            severity=self.severity_default,
            url=f"redis://{host}:6379",
            path="",
            description=(
                "A Redis server is accessible on port 6379 without authentication. "
                "Attackers can read all cached data, write arbitrary keys (including "
                "session hijacking), and in some configurations achieve RCE via "
                "the CONFIG SET or module load commands."
            ),
            remediation=(
                "Set requirepass in redis.conf to require authentication. "
                "Bind Redis to 127.0.0.1 (bind 127.0.0.1). "
                "Apply firewall rules to block port 6379 from public networks. "
                "Enable protected-mode yes."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class MongoExposed(Detection):
    """MongoDB server accessible without authentication on port 27017."""

    id = "network_services.mongo.exposed"
    name = "MongoDB Server Exposed"
    category = "network_service_exposure"
    severity_default = 950
    cwe = "CWE-306"
    tags = ("mongodb", "database", "unauthenticated", "nosql")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return asset.port == 27017

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        host = asset.ip or asset.host
        # MongoDB sends a binary handshake on connect; we read the banner
        result = await grab_banner(host, 27017)
        if not result.connected:
            return
        banner = result.banner
        if not banner:
            # MongoDB may need an OP_QUERY to respond; try HTTP API (mongod with REST)
            http_result = await grab_banner(
                host, 27017,
                probe=b"GET / HTTP/1.0\r\n\r\n"
            )
            banner = http_result.banner

        # MongoDB wire protocol starts with a 4-byte little-endian message length
        # It won't send plain text unless it's REST API mode or old version
        # Accept if banner starts with binary data or contains "MongoDB" indicators
        is_mongo = (
            b"MongoDB" in banner
            or b"mongodb" in banner
            or (len(banner) >= 4 and banner[4:5] in (b"\x01", b"\x02", b"\xd7", b"\xdb"))
        )
        if not is_mongo:
            # Try probing via HTTP (some MongoDB setups expose REST API)
            return

        from bounty.models import ProbeResult
        fake_pr = ProbeResult(
            url=f"mongodb://{host}:27017",
            final_url=f"mongodb://{host}:27017",
            status_code=200,
            headers={},
            body=banner,
            body_text=banner.decode("utf-8", errors="replace"),
        )
        await ctx.capture_evidence(f"mongodb://{host}:27017", fake_pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"MongoDB server exposed without auth at {asset.host}:27017",
            category=self.category,
            severity=self.severity_default,
            url=f"mongodb://{host}:27017",
            path="",
            description=(
                "A MongoDB server is accessible on port 27017 without authentication. "
                "Attackers can enumerate all databases, read and modify all collections, "
                "and exfiltrate the entire dataset."
            ),
            remediation=(
                "Enable MongoDB authentication: set security.authorization: enabled "
                "in mongod.conf. Bind to 127.0.0.1 via net.bindIp. "
                "Apply network-level firewall rules to block port 27017."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class ElasticsearchHttpExposed(Detection):
    """Elasticsearch cluster accessible over HTTP on port 9200 without authentication.

    This complements the admin_panels detection (which checks the UI);
    this covers raw open clusters without an admin UI wrapper.
    """

    id = "network_services.elasticsearch.http_exposed"
    name = "Elasticsearch HTTP API Exposed (Open Cluster)"
    category = "network_service_exposure"
    severity_default = 700
    cwe = "CWE-306"
    tags = ("elasticsearch", "database", "unauthenticated", "search")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return asset.port == 9200

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # Elasticsearch root returns {"name": "...", "cluster_name": "...", "version": {...}}
        if "cluster_name" not in data or "version" not in data:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Elasticsearch cluster exposed (no auth) at {asset.host}:9200",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"An Elasticsearch cluster ({data.get('cluster_name', 'unknown')}) "
                "is accessible on port 9200 without authentication. "
                "Attackers can read all indices, search all data, and in some "
                "versions achieve RCE via Groovy/Painless script execution."
            ),
            remediation=(
                "Enable X-Pack security with authentication. "
                "Bind Elasticsearch to internal interfaces only. "
                "Apply network-level firewall rules to block port 9200."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class PostgresExposed(Detection):
    """PostgreSQL server accessible on port 5432 from public networks."""

    id = "network_services.postgres.exposed"
    name = "PostgreSQL Server Exposed"
    category = "network_service_exposure"
    severity_default = 950
    cwe = "CWE-306"
    tags = ("postgresql", "database", "unauthenticated", "sql")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return asset.port == 5432

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        host = asset.ip or asset.host
        # PostgreSQL responds to an SSL request or startup message
        # We send an SSL negotiation request to get a definitive response
        # SSL request: 8-byte message (length=8, SSLRequest=80877103)
        ssl_request = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
        result = await grab_banner(host, 5432, probe=ssl_request)
        if not result.connected:
            return
        banner = result.banner
        # PostgreSQL responds with 'S' (SSL supported), 'N' (SSL not supported),
        # or 'E' (error) + then Postgres error message
        is_postgres = (
            banner[:1] in (b"S", b"N", b"E")  # SSL response codes
            or b"PostgreSQL" in banner
            or b"FATAL" in banner
            or b"authentication" in banner.lower()
        )
        if not is_postgres:
            return

        from bounty.models import ProbeResult
        fake_pr = ProbeResult(
            url=f"postgresql://{host}:5432",
            final_url=f"postgresql://{host}:5432",
            status_code=200,
            headers={},
            body=banner,
            body_text=banner.decode("utf-8", errors="replace"),
        )
        await ctx.capture_evidence(f"postgresql://{host}:5432", fake_pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"PostgreSQL server exposed at {asset.host}:5432",
            category=self.category,
            severity=self.severity_default,
            url=f"postgresql://{host}:5432",
            path="",
            description=(
                "A PostgreSQL server is accessible on port 5432 from the public "
                "internet. Even with password auth required, this exposes the "
                "database to brute-force attacks and version-specific exploits."
            ),
            remediation=(
                "Restrict PostgreSQL to localhost or private network interfaces. "
                "Apply pg_hba.conf rules to limit client IP addresses. "
                "Use firewall rules to block port 5432 from public networks."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class MysqlExposed(Detection):
    """MySQL/MariaDB server accessible on port 3306 from public networks."""

    id = "network_services.mysql.exposed"
    name = "MySQL/MariaDB Server Exposed"
    category = "network_service_exposure"
    severity_default = 950
    cwe = "CWE-306"
    tags = ("mysql", "mariadb", "database", "sql")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return asset.port == 3306

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        host = asset.ip or asset.host
        result = await grab_banner(host, 3306)
        if not result.connected:
            return
        banner = result.banner
        # MySQL handshake: starts with 3-byte packet length + 1-byte sequence + protocol version
        # Protocol version is 0x0a (10) for MySQL 4.1+
        # The banner contains the version string soon after
        is_mysql = (
            b"MySQL" in banner
            or b"MariaDB" in banner
            or b"mysql" in banner.lower()
            or (len(banner) >= 5 and banner[4:5] == b"\x0a")  # Protocol version 10
        )
        if not is_mysql:
            return

        from bounty.models import ProbeResult
        fake_pr = ProbeResult(
            url=f"mysql://{host}:3306",
            final_url=f"mysql://{host}:3306",
            status_code=200,
            headers={},
            body=banner,
            body_text=banner.decode("utf-8", errors="replace"),
        )
        await ctx.capture_evidence(f"mysql://{host}:3306", fake_pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"MySQL server exposed at {asset.host}:3306",
            category=self.category,
            severity=self.severity_default,
            url=f"mysql://{host}:3306",
            path="",
            description=(
                "A MySQL/MariaDB server is accessible on port 3306 from the public "
                "internet. The server banner reveals the exact version. "
                "This exposes the database to brute-force, version exploits, and "
                "unauthorized access attempts."
            ),
            remediation=(
                "Bind MySQL to 127.0.0.1 in my.cnf: bind-address = 127.0.0.1. "
                "Remove public firewall access to port 3306. "
                "Use SSH tunnels or VPN for remote database access."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


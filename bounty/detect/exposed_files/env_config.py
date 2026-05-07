"""
bounty.detect.exposed_files.env_config — Exposed environment & config file detections.

Ten detections covering .env files, framework config backups, application
configs, secrets, and infrastructure files.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.detect.exposed_files._common import is_real_file_response
from bounty.models import Asset, FindingDraft, FingerprintResult

# ---------------------------------------------------------------------------
# .env file
# ---------------------------------------------------------------------------

_ENV_KEY_VALUE_RE = re.compile(rb"^[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE)
_HIGH_VALUE_ENV_KEYS = (
    b"AWS_",
    b"STRIPE_",
    b"DB_",
    b"DATABASE_",
    b"MYSQL_",
    b"POSTGRES_",
    b"REDIS_",
    b"SECRET",
    b"PASSWORD",
    b"MAIL_",
    b"SMTP_",
    b"API_KEY",
    b"APP_KEY",
    b"PRIVATE_KEY",
    b"GITHUB_TOKEN",
    b"TWILIO_",
    b"SENDGRID_",
)

_ENV_PATHS = [
    "/.env",
    "/.env.backup",
    "/.env.bak",
    "/.env.local",
    "/.env.dev",
    "/.env.prod",
    "/.env.production",
    "/.env.staging",
    "/.env.save",
    "/.env.old",
    "/api/.env",
    "/admin/.env",
    "/app/.env",
]


class ExposedEnvFile(Detection):
    """Exposed .env configuration file."""

    id = "exposed.env_config.env"
    name = "Exposed .env file"
    category = "exposed_config"
    severity_default = 400
    cwe = "CWE-312"
    tags = ("exposed-files", "env-leak")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _ENV_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, [b"="]):
                continue
            # Must have KEY=VALUE pattern
            if not _ENV_KEY_VALUE_RE.search(pr.body):
                continue

            # Score severity by content
            high_count = sum(1 for k in _HIGH_VALUE_ENV_KEYS if k in pr.body.upper())
            if high_count >= 3:
                sev = 900
            elif high_count >= 1:
                sev = 800
            else:
                sev = 400

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed .env file at {asset.host}{path}",
                category=self.category,
                severity=sev,
                url=url,
                path=path,
                description=(
                    f"An environment configuration file ({path}) is publicly "
                    "accessible. It may contain database credentials, API keys, "
                    "and other secrets used by the application."
                ),
                remediation=(
                    "Immediately block access to .env files at the web server level "
                    "(nginx: `location ~ /\\.env { deny all; }`). "
                    "Rotate any exposed credentials."
                ),
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return  # Only report the first confirmed path


# ---------------------------------------------------------------------------
# WordPress config backup
# ---------------------------------------------------------------------------

_WP_CONFIG_PATHS = [
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php~",
    "/wp-config.txt",
    "/wp-config.php.swp",
]


class ExposedWpConfigBackup(Detection):
    """Exposed wp-config.php backup — WordPress database credentials."""

    id = "exposed.env_config.wp-config-backup"
    name = "Exposed wp-config.php backup"
    category = "exposed_config"
    severity_default = 800
    cwe = "CWE-312"
    tags = ("exposed-files", "wordpress", "credentials")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return any(
            fp.tech == "wordpress" and fp.confidence in ("weak", "strong", "definitive")
            for fp in fingerprints
        )

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _WP_CONFIG_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, [b"<?php", b"DB_PASSWORD", b"AUTH_KEY"]):
                continue
            if b"DB_PASSWORD" not in pr.body and b"AUTH_KEY" not in pr.body:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed wp-config.php backup at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    "A WordPress configuration backup file is publicly accessible, "
                    "exposing database credentials and secret keys."
                ),
                remediation=(
                    "Delete the backup file and rotate all credentials in wp-config.php. "
                    "Block access to .php.bak, .php.old, etc. at the web server."
                ),
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Generic PHP config backup
# ---------------------------------------------------------------------------

_CONFIG_PHP_PATHS = [
    "/config.php.bak",
    "/config.php~",
    "/config.php.save",
    "/config.inc.php",
    "/configuration.php.bak",
    "/includes/config.php",
]


class ExposedConfigPhp(Detection):
    """Exposed PHP config file backup."""

    id = "exposed.env_config.config-php"
    name = "Exposed PHP config backup"
    category = "exposed_config"
    severity_default = 700
    cwe = "CWE-540"
    tags = ("exposed-files",)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _CONFIG_PHP_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, [b"<?php", b"$"]):
                continue
            if b"<?php" not in pr.body:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed PHP config backup at {asset.host}{path}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description="A PHP configuration file backup is publicly accessible.",
                remediation="Remove the backup file and block access to .php.bak files.",
                cwe="CWE-540",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Java/Spring application config
# ---------------------------------------------------------------------------

_JAVA_CONFIG_PATHS = [
    "/application.yml",
    "/application.properties",
    "/application-dev.yml",
    "/application-prod.yml",
    "/bootstrap.yml",
    "/config/application.yml",
]

_SPRING_KEYS = (b"spring.", b"server.", b"datasource.", b"management.", b"logging.")
_SPRING_SECRET_KEYS = (b"password", b"secret", b"credential", b"token", b"key")


class ExposedJavaApplicationConfig(Detection):
    """Exposed Spring Boot / Java application config."""

    id = "exposed.env_config.java-app-config"
    name = "Exposed Java/Spring application config"
    category = "exposed_config"
    severity_default = 400
    cwe = "CWE-312"
    tags = ("exposed-files", "java", "spring")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        java_techs = {"java", "spring", "java_spring", "spring-boot"}
        return any(
            fp.tech.lower() in java_techs and fp.confidence in ("weak", "strong", "definitive")
            for fp in fingerprints
        )

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _JAVA_CONFIG_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, list(_SPRING_KEYS)):
                continue
            if not any(k in pr.body for k in _SPRING_KEYS):
                continue

            has_secrets = any(k in pr.body.lower() for k in _SPRING_SECRET_KEYS)
            sev = 800 if has_secrets else 400

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed Java/Spring config at {asset.host}{path}",
                category=self.category,
                severity=sev,
                url=url,
                path=path,
                description=(
                    "A Java/Spring application configuration file is publicly accessible, "
                    "potentially exposing datasource credentials and service secrets."
                ),
                remediation="Move config files outside the web root or restrict access.",
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Rails credentials
# ---------------------------------------------------------------------------

_RAILS_CONFIG_PATHS = [
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/master.key",
    "/config/credentials.yml.enc",
]


class ExposedRailsCredentials(Detection):
    """Exposed Rails database.yml or secrets.yml."""

    id = "exposed.env_config.rails-credentials"
    name = "Exposed Rails credentials file"
    category = "exposed_config"
    severity_default = 800
    cwe = "CWE-312"
    tags = ("exposed-files", "rails", "credentials")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        rails_techs = {"rails", "ruby-on-rails", "rails-hotwire"}
        return any(
            fp.tech.lower() in rails_techs and fp.confidence in ("weak", "strong", "definitive")
            for fp in fingerprints
        )

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _RAILS_CONFIG_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            sigs: list[bytes]
            if "database.yml" in path:
                sigs = [b"adapter:", b"database:", b"password:"]
            elif "secrets.yml" in path:
                sigs = [b"secret_key_base:", b"production:"]
            elif "master.key" in path:
                sigs = [b""]  # Any non-empty 32-char hex string
                if pr.status_code == 200 and len(pr.body) in (32, 33, 64, 65):
                    sigs = [pr.body[:4]]  # Just confirm it's non-trivial
            else:
                sigs = [b"encrypted:"]

            if not is_real_file_response(pr, sigs):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed Rails config at {asset.host}{path}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=f"A Rails credentials file ({path}) is publicly accessible.",
                remediation="Move config files outside the web root and rotate credentials.",
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Terraform state
# ---------------------------------------------------------------------------

_TF_PATHS = [
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
]


class ExposedTerraformState(Detection):
    """Exposed terraform.tfstate — contains all infra secrets in plaintext."""

    id = "exposed.env_config.terraform-state"
    name = "Exposed Terraform state file"
    category = "exposed_config"
    severity_default = 950
    cwe = "CWE-312"
    tags = ("exposed-files", "terraform", "credentials", "infrastructure")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _TF_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, [b'"terraform_version"', b'"resources"']):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed Terraform state file at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    "A Terraform state file is publicly accessible. Terraform state "
                    "files contain every secret and credential used to provision "
                    "infrastructure in plaintext, including cloud access keys, "
                    "database passwords, and TLS private keys."
                ),
                remediation=(
                    "Store Terraform state in a secure backend (S3+KMS, Terraform Cloud). "
                    "Never commit or serve state files publicly. Rotate all exposed secrets."
                ),
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------

_DOCKER_PATHS = [
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/docker-compose.override.yml",
    "/Dockerfile",
]


class ExposedDockerCompose(Detection):
    """Exposed Docker Compose / Dockerfile."""

    id = "exposed.env_config.docker-compose"
    name = "Exposed Docker Compose file"
    category = "exposed_config"
    severity_default = 500
    cwe = "CWE-312"
    tags = ("exposed-files", "docker")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _DOCKER_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if "Dockerfile" in path:
                sigs: list[bytes] = [b"FROM ", b"RUN ", b"CMD "]
            else:
                sigs = [b"services:", b"version:", b"image:"]
            if not is_real_file_response(pr, sigs):
                continue

            has_env = b"environment:" in pr.body or b"POSTGRES_PASSWORD" in pr.body
            sev = 800 if has_env else 500

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed {path.lstrip('/')} at {asset.host}",
                category=self.category,
                severity=sev,
                url=url,
                path=path,
                description=(
                    f"A Docker configuration file ({path}) is publicly accessible, "
                    "potentially revealing internal service topology and credentials."
                ),
                remediation="Remove Docker config files from the web root.",
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Kubernetes config
# ---------------------------------------------------------------------------

_KUBE_PATHS = [
    "/kubeconfig",
    "/.kube/config",
    "/kube.config",
]


class ExposedKubeConfig(Detection):
    """Exposed kubeconfig — full Kubernetes cluster access."""

    id = "exposed.env_config.kubeconfig"
    name = "Exposed Kubernetes config"
    category = "exposed_config"
    severity_default = 950
    cwe = "CWE-312"
    tags = ("exposed-files", "kubernetes", "credentials", "infrastructure")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _KUBE_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(
                pr, [b"apiVersion: v1", b"clusters:", b"users:"]
            ):
                continue
            if b"apiVersion" not in pr.body:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed Kubernetes config at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    "A Kubernetes configuration file is publicly accessible, "
                    "providing full cluster access credentials to an attacker."
                ),
                remediation="Remove the kubeconfig file from the web root immediately and rotate cluster credentials.",
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Private key
# ---------------------------------------------------------------------------

_PRIVKEY_PATHS = [
    "/id_rsa",
    "/id_dsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/server.key",
    "/private.key",
    "/ssl.key",
    "/.ssh/id_rsa",
    "/server.pem",
]


class ExposedPrivateKey(Detection):
    """Exposed PEM private key file."""

    id = "exposed.env_config.private-key"
    name = "Exposed private key"
    category = "exposed_config"
    severity_default = 950
    cwe = "CWE-312"
    tags = ("exposed-files", "credentials", "private-key")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _PRIVKEY_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, [b"-----BEGIN ", b"PRIVATE KEY-----"]):
                continue
            if b"PRIVATE KEY" not in pr.body:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed private key at {asset.host}{path}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    f"A PEM private key file ({path}) is publicly accessible. "
                    "This allows an attacker to impersonate the server, decrypt traffic, "
                    "or authenticate to services using the exposed key pair."
                ),
                remediation=(
                    "Remove the private key from the web root immediately. "
                    "Revoke the key and reissue all associated certificates."
                ),
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# .DS_Store
# ---------------------------------------------------------------------------


class ExposedDsStore(Detection):
    """Exposed .DS_Store macOS metadata file."""

    id = "exposed.env_config.ds-store"
    name = "Exposed .DS_Store file"
    category = "exposed_config"
    severity_default = 200
    cwe = "CWE-548"
    tags = ("exposed-files", "information-disclosure")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        url = f"{asset.url.rstrip('/')}/.DS_Store"
        pr = await ctx.probe_fn(url)
        # DS_Store magic: 00 00 00 01 42 75 64 31 (Bud1)
        if not is_real_file_response(pr, [b"\x00\x00\x00\x01Bud1", b"Bud1"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.DS_Store",
            title=f"Exposed .DS_Store at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/.DS_Store",
            description=(
                "A macOS .DS_Store metadata file is publicly accessible. "
                "It reveals the directory structure, file names, and layout "
                "of the developer's local filesystem, which can be used to "
                "enumerate other sensitive files."
            ),
            remediation=(
                "Delete .DS_Store files from the web root and use a .gitignore / "
                ".hgignore rule to prevent them from being committed."
            ),
            cwe="CWE-548",
            tags=list(self.tags),
        )


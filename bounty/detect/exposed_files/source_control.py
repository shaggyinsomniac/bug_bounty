"""
bounty.detect.exposed_files.source_control — Exposed source-control detections.

Seven detections covering Git, SVN, Mercurial, Bazaar, Git credentials,
GitLab CI config, and GitHub workflow directory listings.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.detect.exposed_files._common import is_real_file_response
from bounty.models import Asset, FindingDraft, FingerprintResult

# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------


class ExposedGitDirectory(Detection):
    """Exposed /.git/ directory — full source code disclosure."""

    id = "exposed.source_control.git"
    name = "Exposed .git directory"
    category = "exposed_source_control"
    severity_default = 700
    cwe = "CWE-540"
    tags = ("exposed-files", "source-leak")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")

        # Cheapest signal first: /.git/HEAD
        head_url = f"{base}/.git/HEAD"
        pr_head = await ctx.probe_fn(head_url)
        if not is_real_file_response(pr_head, [b"ref: refs/heads/", b"ref: refs/"]):
            return

        # Confirm with /.git/config
        cfg_url = f"{base}/.git/config"
        pr_cfg = await ctx.probe_fn(cfg_url)
        if not is_real_file_response(pr_cfg, [b"[core]", b"repositoryformatversion"]):
            return

        await ctx.capture_evidence(head_url, pr_head)
        await ctx.capture_evidence(cfg_url, pr_cfg)

        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.git/",
            title=f"Exposed .git directory at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=head_url,
            path="/.git/",
            description=(
                "The /.git/ directory is publicly accessible, exposing the full "
                "repository structure including commit history, branches, and any "
                "secrets that were ever committed."
            ),
            remediation=(
                "Remove .git/ from web-served directories, or configure the web "
                "server to deny /.git/* requests "
                "(nginx: `location ~ /\\.git { deny all; }`)."
            ),
            cwe="CWE-540",
            tags=list(self.tags),
        )


class ExposedGitCredentials(Detection):
    """Exposed /.git-credentials file — plain-text Git credentials."""

    id = "exposed.source_control.git-credentials"
    name = "Exposed .git-credentials"
    category = "exposed_source_control"
    severity_default = 900
    cwe = "CWE-312"
    tags = ("exposed-files", "credentials")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        url = f"{asset.url.rstrip('/')}/.git-credentials"
        pr = await ctx.probe_fn(url)
        if not is_real_file_response(pr, [b"https://", b"http://"]):
            return
        # Must contain user:pass@ pattern to be actual credentials
        if b":@" not in pr.body and b"@" not in pr.body:
            return
        if b"://" not in pr.body:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.git-credentials",
            title=f"Exposed .git-credentials at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/.git-credentials",
            description=(
                "A .git-credentials file is publicly accessible containing "
                "plain-text Git credentials (username and password/token). "
                "Attackers can use these to authenticate to your repositories."
            ),
            remediation=(
                "Delete or block access to /.git-credentials. "
                "Rotate any credentials found in the file immediately."
            ),
            cwe="CWE-312",
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# SVN
# ---------------------------------------------------------------------------


class ExposedSvnDirectory(Detection):
    """Exposed /.svn/ directory."""

    id = "exposed.source_control.svn"
    name = "Exposed .svn directory"
    category = "exposed_source_control"
    severity_default = 700
    cwe = "CWE-540"
    tags = ("exposed-files", "source-leak")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        entries_url = f"{base}/.svn/entries"
        pr = await ctx.probe_fn(entries_url)

        # SVN entries file starts with a version number on first line (digits)
        valid = is_real_file_response(pr, [b"10\n", b"8\n", b"9\n"]) or (
            pr.status_code == 200
            and len(pr.body) > 10
            and pr.body[:4].isdigit()
        )
        if not valid:
            # Try wc.db (SVN >= 1.7)
            wc_url = f"{base}/.svn/wc.db"
            pr = await ctx.probe_fn(wc_url)
            if not is_real_file_response(pr, [b"SQLite format 3"]):
                return
            entries_url = wc_url

        await ctx.capture_evidence(entries_url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.svn/",
            title=f"Exposed .svn directory at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=entries_url,
            path="/.svn/",
            description="The /.svn/ working-copy directory is publicly accessible.",
            remediation="Deny access to /.svn/* in your web server configuration.",
            cwe="CWE-540",
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# Mercurial (HG)
# ---------------------------------------------------------------------------


class ExposedHgDirectory(Detection):
    """Exposed /.hg/ Mercurial directory."""

    id = "exposed.source_control.hg"
    name = "Exposed .hg directory"
    category = "exposed_source_control"
    severity_default = 700
    cwe = "CWE-540"
    tags = ("exposed-files", "source-leak")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        req_url = f"{base}/.hg/requires"
        pr = await ctx.probe_fn(req_url)
        if not is_real_file_response(pr, [b"revlogv1", b"store", b"fncache"]):
            return

        await ctx.capture_evidence(req_url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.hg/",
            title=f"Exposed .hg directory at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=req_url,
            path="/.hg/",
            description="The /.hg/ Mercurial repository directory is publicly accessible.",
            remediation="Deny access to /.hg/* in your web server configuration.",
            cwe="CWE-540",
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# Bazaar (BZR)
# ---------------------------------------------------------------------------


class ExposedBzrDirectory(Detection):
    """Exposed /.bzr/ Bazaar directory."""

    id = "exposed.source_control.bzr"
    name = "Exposed .bzr directory"
    category = "exposed_source_control"
    severity_default = 700
    cwe = "CWE-540"
    tags = ("exposed-files", "source-leak")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        url = f"{base}/.bzr/branch/branch.conf"
        pr = await ctx.probe_fn(url)
        if not is_real_file_response(pr, [b"[DEFAULT]", b"bound_location", b"parent_location"]):
            # Fallback: /.bzr/README
            url2 = f"{base}/.bzr/README"
            pr2 = await ctx.probe_fn(url2)
            if not is_real_file_response(pr2, [b"This is a Bazaar", b"bzr.launchpad"]):
                return
            url = url2
            pr = pr2

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.bzr/",
            title=f"Exposed .bzr directory at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/.bzr/",
            description="The /.bzr/ Bazaar repository directory is publicly accessible.",
            remediation="Deny access to /.bzr/* in your web server configuration.",
            cwe="CWE-540",
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# GitLab CI
# ---------------------------------------------------------------------------


class ExposedGitlabCi(Detection):
    """Exposed /.gitlab-ci.yml with credential markers."""

    id = "exposed.source_control.gitlab-ci"
    name = "Exposed .gitlab-ci.yml with credentials"
    category = "exposed_source_control"
    severity_default = 300
    cwe = "CWE-312"
    tags = ("exposed-files",)

    _CRED_PATTERNS = (
        b"AWS_",
        b"DOCKER_",
        b"SECRET",
        b"PASSWORD",
        b"TOKEN",
        b"API_KEY",
        b"PRIVATE_KEY",
        b"GITHUB_TOKEN",
    )

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        url = f"{asset.url.rstrip('/')}/.gitlab-ci.yml"
        pr = await ctx.probe_fn(url)
        # YAML is text; allow_html=False but yaml has no DOCTYPE
        if not is_real_file_response(pr, [b"stages:", b"image:", b"script:", b"variables:"]):
            return

        has_creds = any(p in pr.body for p in self._CRED_PATTERNS)
        if not has_creds:
            return  # Low-severity if no creds visible — skip

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.gitlab-ci.yml",
            title=f"Exposed .gitlab-ci.yml with credential markers at {asset.host}",
            category=self.category,
            severity=600,  # Elevated because creds visible
            url=url,
            path="/.gitlab-ci.yml",
            description=(
                "The /.gitlab-ci.yml CI/CD config file is public and contains "
                "potential credential environment variable names. These may "
                "expose secrets if CI variables leak to public pipelines."
            ),
            remediation=(
                "Review whether this file should be public. Move secrets to "
                "GitLab CI/CD variables (protected + masked), not hardcoded."
            ),
            cwe="CWE-312",
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# GitHub Workflows directory listing
# ---------------------------------------------------------------------------


class ExposedGithubWorkflows(Detection):
    """Exposed /.github/workflows/ directory listing."""

    id = "exposed.source_control.github-workflows"
    name = "Exposed .github/workflows/ directory listing"
    category = "exposed_source_control"
    severity_default = 200
    cwe = "CWE-548"
    tags = ("exposed-files",)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        url = f"{asset.url.rstrip('/')}/.github/workflows/"
        pr = await ctx.probe_fn(url)
        # Directory listing has HTML but contains specific title pattern
        if pr.status_code != 200:
            return
        body_lower = pr.body.lower()
        if b"index of /.github" not in body_lower and b"directory listing" not in body_lower:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/.github/workflows/",
            title=f"Exposed .github/workflows directory listing at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/.github/workflows/",
            description=(
                "Directory listing is enabled for /.github/workflows/, "
                "exposing GitHub Actions workflow files. These may reveal "
                "pipeline secrets, deployment patterns, or internal tooling."
            ),
            remediation="Disable directory listing in your web server configuration.",
            cwe="CWE-548",
            tags=list(self.tags),
        )


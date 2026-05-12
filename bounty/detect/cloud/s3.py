"""
bounty.detect.cloud.s3 — AWS S3 bucket misconfiguration detections.

Two detections:
- S3BucketListing  — Bucket lists objects (ListBucketResult in response)
- S3PolicyExposed  — Bucket policy accessible via GET ?policy
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class S3BucketListing(Detection):
    """AWS S3 bucket allows anonymous listing of objects."""

    id = "cloud.s3.bucket_listing"
    name = "AWS S3 Bucket Listing Enabled"
    category = "cloud_misconfiguration"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("cloud", "s3", "aws", "bucket-listing")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True  # Check all assets — S3 may be on any domain/path

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        # Try the root URL and common S3 paths
        urls_to_check = [asset.url.rstrip("/") + "/"]
        for path_suffix in ["", "/?list-type=2", "/?max-keys=10"]:
            url = asset.url.rstrip("/") + path_suffix
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body = pr.body
            if b"<ListBucketResult" not in body:
                continue
            # Confirm it looks like a real S3 listing
            if b"<Contents>" not in body and b"<Name>" not in body and b"<Prefix>" not in body:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}",
                title=f"S3 bucket listing enabled at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path_suffix or "/",
                description=(
                    "The S3 bucket allows anonymous listing of its contents. "
                    "Attackers can enumerate all stored objects, potentially "
                    "discovering sensitive files, backups, or customer data."
                ),
                remediation=(
                    "Disable public bucket ACLs and block public access via "
                    "S3 Block Public Access settings. Review bucket policies "
                    "and remove any s3:ListBucket grants to 'AllUsers'."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return


class S3PolicyExposed(Detection):
    """AWS S3 bucket policy accessible publicly via GET ?policy."""

    id = "cloud.s3.policy_exposed"
    name = "AWS S3 Bucket Policy Exposed"
    category = "cloud_misconfiguration"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("cloud", "s3", "aws", "bucket-policy")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/?policy"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_text = pr.body_text.strip()
        if not body_text:
            return
        # Must parse as JSON and look like a bucket policy
        try:
            data = json.loads(body_text)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(data, dict):
            return
        # S3 bucket policy has Statement key
        if "Statement" not in data and "Version" not in data:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"S3 bucket policy exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The S3 bucket policy is accessible publicly. It reveals the "
                "IAM permissions and principals that can access the bucket, "
                "aiding privilege escalation and lateral movement mapping."
            ),
            remediation=(
                "Remove public read access to the bucket policy. Review and "
                "restrict ?policy access to authorized principals only."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


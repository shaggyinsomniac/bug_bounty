"""
bounty.detect.cloud.gcp — Google Cloud Platform storage detections.

Two detections:
- GcpStorageBucketListing — GCS bucket listing accessible anonymously
- GcpMetadataLeak         — GCP metadata server accessible from target
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class GcpStorageBucketListing(Detection):
    """GCS bucket listing accessible without authentication."""

    id = "cloud.gcp.storage_bucket_listing"
    name = "GCP Storage Bucket Listing Exposed"
    category = "cloud_misconfiguration"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("cloud", "gcp", "gcs", "bucket-listing")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body
        # GCS XML API listing contains these markers
        if b"<ListBucketResult" in body:
            # Could also be S3-compatible — check for GCS-specific indicator
            if b"storage.googleapis.com" not in body and b"<Name>" in body:
                # Generic listing — could be GCS, report it
                pass
        # GCS JSON API response
        elif b'"kind": "storage#objects"' in body or b'"items"' in body:
            try:
                data = json.loads(pr.body_text)
                if not isinstance(data, dict) or "items" not in data:
                    return
            except (ValueError, UnicodeDecodeError):
                return
        else:
            return
        # Confirm it's GCS by host or headers
        headers = {k.lower(): v for k, v in pr.headers.items()}
        is_gcs = (
            "storage.googleapis.com" in asset.host
            or "storage.googleapis.com" in pr.final_url
            or "x-guploader-uploadid" in headers
            or "storage#buckets" in pr.body_text
            or "storage#objects" in pr.body_text
        )
        if not is_gcs and b"storage.googleapis.com" not in body:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"GCP storage bucket listing exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                "A GCP Cloud Storage bucket allows anonymous listing of its contents. "
                "All objects can be enumerated without authentication."
            ),
            remediation=(
                "Remove 'allUsers' and 'allAuthenticatedUsers' from bucket IAM "
                "bindings. Enable Uniform Bucket-Level Access in GCP Console."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class GcpMetadataLeak(Detection):
    """GCP metadata server accessible from target — SSRF validation.

    Only fires if the metadata endpoint actually responds with GCP metadata,
    indicating either a misconfigured SSRF on the target or a mis-routed
    network segment.
    """

    id = "cloud.gcp.metadata_leak"
    name = "GCP Metadata Server Accessible"
    category = "cloud_misconfiguration"
    severity_default = 800
    cwe = "CWE-918"
    tags = ("cloud", "gcp", "metadata", "ssrf")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        # This checks if the asset *is* 169.254.169.254 or metadata.google.internal
        if "169.254.169.254" not in asset.host and "metadata.google.internal" not in asset.host:
            return

        path = "/computeMetadata/v1/?recursive=true"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body_text
        # GCP metadata returns JSON with specific keys
        if not any(k in body for k in ["project-id", "instance-id", "service-accounts", "email"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"GCP metadata server accessible at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The GCP instance metadata server (169.254.169.254) is accessible. "
                "It exposes service account tokens, project IDs, and instance details "
                "that enable lateral movement within the cloud environment."
            ),
            remediation=(
                "Block outbound access to 169.254.169.254 at the host firewall level. "
                "Enable GCP metadata server v1 (which requires a specific header). "
                "Audit workloads that legitimately need metadata access."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


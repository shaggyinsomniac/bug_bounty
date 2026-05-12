"""
bounty.detect.cloud.azure — Azure storage misconfiguration detections.

Two detections:
- AzureStorageContainerListing — ?comp=list returns container/blob list
- AzureBlobAnonAccess          — anonymous access to Azure Blob container
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class AzureStorageContainerListing(Detection):
    """Azure Blob Storage container listing accessible via ?comp=list."""

    id = "cloud.azure.container_listing"
    name = "Azure Storage Container Listing Exposed"
    category = "cloud_misconfiguration"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("cloud", "azure", "blob-storage", "listing")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/?comp=list"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body
        # Azure returns XML with EnumerationResults
        if b"<EnumerationResults" not in body:
            return
        if b"<Blobs>" not in body and b"<Containers>" not in body and b"<Container>" not in body:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Azure storage container listing exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "Azure Blob Storage allows anonymous container/blob listing. "
                "Attackers can enumerate all stored objects without authentication."
            ),
            remediation=(
                "Set the container access level to 'Private' in Azure Portal. "
                "Enable Azure Defender for Storage and review shared access signatures."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class AzureBlobAnonAccess(Detection):
    """Azure Blob container allows anonymous public read access."""

    id = "cloud.azure.blob_anon_access"
    name = "Azure Blob Anonymous Public Access"
    category = "cloud_misconfiguration"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("cloud", "azure", "blob-storage", "anonymous-access")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        # Check for Azure blob storage indicator headers on root URL
        url = asset.url.rstrip("/") + "/"
        pr = await ctx.probe_fn(url)
        # Azure blob storage responses contain specific headers
        headers = {k.lower(): v for k, v in pr.headers.items()}
        is_azure = (
            "x-ms-request-id" in headers
            or "x-ms-version" in headers
            or ".blob.core.windows.net" in asset.host
            or ".blob.core.windows.net" in pr.final_url
        )
        if not is_azure:
            return
        if pr.status_code not in (200, 206):
            return
        # If we get a 200 from a blob URL without auth, it's anonymous access
        body = pr.body
        if len(body) < 10:
            return
        # Check it's not an error response
        if b"<Error>" in body and b"PublicAccessNotPermitted" in body:
            return
        if b"<Error>" in body and b"ResourceNotFound" in body:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Azure blob anonymous access at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                "Azure Blob Storage allows anonymous public read access. "
                "Data in this container can be read without authentication."
            ),
            remediation=(
                "Disable 'Allow Blob public access' at the storage account level "
                "in Azure Portal. Audit all containers for public access settings."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


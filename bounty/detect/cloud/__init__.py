"""
bounty.detect.cloud — Cloud storage and CDN misconfiguration detections.

Re-exports all cloud detection classes.
"""

from __future__ import annotations

from bounty.detect.cloud.azure import AzureBlobAnonAccess, AzureStorageContainerListing
from bounty.detect.cloud.gcp import GcpMetadataLeak, GcpStorageBucketListing
from bounty.detect.cloud.generic import CdnCacheBackend, CloudfrontMisconfig
from bounty.detect.cloud.s3 import S3BucketListing, S3PolicyExposed

__all__ = [
    "S3BucketListing",
    "S3PolicyExposed",
    "AzureStorageContainerListing",
    "AzureBlobAnonAccess",
    "GcpStorageBucketListing",
    "GcpMetadataLeak",
    "CdnCacheBackend",
    "CloudfrontMisconfig",
]


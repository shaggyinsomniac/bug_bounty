"""
bounty.detect.cms_specific — CMS-specific detection modules.

Re-exports all detection classes for WordPress, Drupal, Magento, and Joomla.
All detections are fingerprint-gated: they only run against assets where the
corresponding CMS was identified by the fingerprint stage.
"""

from __future__ import annotations

from bounty.detect.cms_specific.drupal import (
    DrupalChangelogExposed,
    DrupalCron,
    DrupalUpdatePhp,
)
from bounty.detect.cms_specific.joomla import (
    JoomlaAdminVersion,
    JoomlaConfigBackup,
)
from bounty.detect.cms_specific.magento import (
    MagentoDownloader,
    MagentoLocalXml,
    MagentoVersionDisclosure,
)
from bounty.detect.cms_specific.wordpress import (
    WpDebugLog,
    WpInstallExposed,
    WpReadmeExposed,
    WpUserEnum,
    XmlrpcExposed,
)

__all__ = [
    # WordPress
    "WpDebugLog",
    "WpInstallExposed",
    "WpReadmeExposed",
    "WpUserEnum",
    "XmlrpcExposed",
    # Drupal
    "DrupalChangelogExposed",
    "DrupalCron",
    "DrupalUpdatePhp",
    # Magento
    "MagentoLocalXml",
    "MagentoDownloader",
    "MagentoVersionDisclosure",
    # Joomla
    "JoomlaConfigBackup",
    "JoomlaAdminVersion",
]


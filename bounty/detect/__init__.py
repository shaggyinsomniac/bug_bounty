"""
bounty.detect — Detection engine registry.

``REGISTERED_DETECTIONS`` is the authoritative list of all active detections.
The runner iterates this list for every asset.

To add a new detection:
  1. Implement a ``Detection`` subclass in the appropriate module.
  2. Import it here and append an instance to ``REGISTERED_DETECTIONS``.
"""

from __future__ import annotations

from bounty.detect.base import Detection, DetectionContext, DetectionError
from bounty.detect.exposed_files.source_control import (
    ExposedBzrDirectory,
    ExposedGitCredentials,
    ExposedGitDirectory,
    ExposedGitlabCi,
    ExposedGithubWorkflows,
    ExposedHgDirectory,
    ExposedSvnDirectory,
)
from bounty.detect.exposed_files.env_config import (
    ExposedConfigPhp,
    ExposedDockerCompose,
    ExposedDsStore,
    ExposedEnvFile,
    ExposedJavaApplicationConfig,
    ExposedKubeConfig,
    ExposedPrivateKey,
    ExposedRailsCredentials,
    ExposedTerraformState,
    ExposedWpConfigBackup,
)
from bounty.detect.exposed_files.backups import (
    ExposedDatabaseDump,
    ExposedEditorSwap,
    ExposedFilesystemBackup,
    ExposedSourceMap,
)

__all__ = [
    "Detection",
    "DetectionContext",
    "DetectionError",
    "REGISTERED_DETECTIONS",
]

# ---------------------------------------------------------------------------
# Registry — all active detection instances, in priority order.
# ---------------------------------------------------------------------------

REGISTERED_DETECTIONS: list[Detection] = [
    # ── Category 1: Exposed source control (7) ──────────────────────────
    ExposedGitDirectory(),
    ExposedGitCredentials(),
    ExposedSvnDirectory(),
    ExposedHgDirectory(),
    ExposedBzrDirectory(),
    ExposedGitlabCi(),
    ExposedGithubWorkflows(),
    # ── Category 2: Exposed env & config (10) ────────────────────────────
    ExposedEnvFile(),
    ExposedWpConfigBackup(),
    ExposedConfigPhp(),
    ExposedJavaApplicationConfig(),
    ExposedRailsCredentials(),
    ExposedTerraformState(),
    ExposedDockerCompose(),
    ExposedKubeConfig(),
    ExposedPrivateKey(),
    ExposedDsStore(),
    # ── Category 3: Exposed backups & archives (4) ───────────────────────
    ExposedDatabaseDump(),
    ExposedFilesystemBackup(),
    ExposedSourceMap(),
    ExposedEditorSwap(),
]


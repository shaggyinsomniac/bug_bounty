"""
bounty.detect.exposed_files — Exposed-file detection subpackage.

Re-exports all detection classes from the three sub-modules so callers
can do:

    from bounty.detect.exposed_files import ExposedGitDirectory, ...

or import the whole package and iterate ``__all__``.
"""

from __future__ import annotations

from bounty.detect.exposed_files.backups import (
    ExposedDatabaseDump,
    ExposedEditorSwap,
    ExposedFilesystemBackup,
    ExposedSourceMap,
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
from bounty.detect.exposed_files.source_control import (
    ExposedBzrDirectory,
    ExposedGitCredentials,
    ExposedGitDirectory,
    ExposedGitlabCi,
    ExposedGithubWorkflows,
    ExposedHgDirectory,
    ExposedSvnDirectory,
)

__all__ = [
    # source_control (7)
    "ExposedGitDirectory",
    "ExposedGitCredentials",
    "ExposedSvnDirectory",
    "ExposedHgDirectory",
    "ExposedBzrDirectory",
    "ExposedGitlabCi",
    "ExposedGithubWorkflows",
    # env_config (10)
    "ExposedEnvFile",
    "ExposedWpConfigBackup",
    "ExposedConfigPhp",
    "ExposedJavaApplicationConfig",
    "ExposedRailsCredentials",
    "ExposedTerraformState",
    "ExposedDockerCompose",
    "ExposedKubeConfig",
    "ExposedPrivateKey",
    "ExposedDsStore",
    # backups (4)
    "ExposedDatabaseDump",
    "ExposedFilesystemBackup",
    "ExposedSourceMap",
    "ExposedEditorSwap",
]


"""
bounty.detect — Detection engine registry.

``REGISTERED_DETECTIONS`` is the authoritative list of all active detections.
The runner iterates this list for every asset.

To add a new detection:
  1. Implement a ``Detection`` subclass in the appropriate module.
  2. Import it here and append an instance to ``REGISTERED_DETECTIONS``.
"""

from __future__ import annotations

from bounty.detect.admin_panels import (
    AdminerLoginExposed,
    AirflowAnonymousAccess,
    AirflowConfigExposed,
    ArgoCDAnonymousAccess,
    ConsulAPIExposed,
    ElasticsearchClusterExposed,
    ElasticsearchIndicesExposed,
    GiteaPublicReposExposed,
    GitLabPublicProjectsExposed,
    GrafanaAnonymousAccess,
    GrafanaSnapshotExposed,
    HarborRegistryExposed,
    JenkinsAnonymousDashboard,
    JenkinsBuildHistoryExposed,
    JenkinsScriptConsole,
    K8sDashboardExposed,
    KibanaAnonymousAccess,
    NexusRepositoryExposed,
    PhpMyAdminLoginExposed,
    PortainerAPIExposed,
    PrometheusMetricsExposed,
    RabbitMQManagementExposed,
    SonarQubeAnonymousAccess,
    SolrAdminConsole,
    SolrCoresExposed,
    VaultUIExposed,
)
from bounty.detect.ai_infra import (
    HuggingFaceSpacesMisconfig,
    OllamaExposed,
    OpenWebUIExposed,
    StableDiffusionExposed,
    TritonExposed,
    VllmExposed,
)
from bounty.detect.api_docs import (
    GraphqlIntrospection,
    GraphqlPlayground,
    OpenApiJsonExposed,
    PostmanCollectionExposed,
    SwaggerUiExposed,
)
from bounty.detect.base import Detection, DetectionContext, DetectionError
from bounty.detect.nuclei_detection import NucleiCveCheck
from bounty.detect.cms_specific import (
    DrupalChangelogExposed,
    DrupalCron,
    DrupalUpdatePhp,
    JoomlaAdminVersion,
    JoomlaConfigBackup,
    MagentoDownloader,
    MagentoLocalXml,
    MagentoVersionDisclosure,
    WpDebugLog,
    WpInstallExposed,
    WpReadmeExposed,
    WpUserEnum,
    XmlrpcExposed,
)
from bounty.detect.cloud import (
    AzureBlobAnonAccess,
    AzureStorageContainerListing,
    CdnCacheBackend,
    CloudfrontMisconfig,
    GcpMetadataLeak,
    GcpStorageBucketListing,
    S3BucketListing,
    S3PolicyExposed,
)
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
from bounty.detect.java_spring import (
    ActuatorEnv,
    ActuatorExposed,
    ActuatorHeapdump,
    ActuatorLoggers,
    H2Console,
)
from bounty.detect.network_services import (
    ElasticsearchHttpExposed,
    MongoExposed,
    MysqlExposed,
    PostgresExposed,
    RedisExposed,
)
from bounty.detect.php_specific import (
    ComposerFilesExposed,
    PhpinfoExposed,
    ServerInfo,
    ServerStatus,
)
from bounty.detect.takeover import SubdomainTakeover
from bounty.detect.cors import (
    CorsWildcardWithCredentials,
    CorsNullOrigin,
    CorsPreflightWildcard,
)
from bounty.detect.mail import (
    SpfMissing,
    SpfWeak,
    DmarcMissing,
    DmarcWeak,
    DkimNotFound,
)
from bounty.detect.dns import ZoneTransferAllowed
from bounty.detect.discovery import RobotsSensitivePaths, SitemapExposed

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
    # ── Category 4: Admin panel exposures (26) ───────────────────────────
    JenkinsAnonymousDashboard(),
    JenkinsScriptConsole(),
    JenkinsBuildHistoryExposed(),
    GrafanaAnonymousAccess(),
    GrafanaSnapshotExposed(),
    KibanaAnonymousAccess(),
    PhpMyAdminLoginExposed(),
    AdminerLoginExposed(),
    SolrAdminConsole(),
    SolrCoresExposed(),
    AirflowAnonymousAccess(),
    AirflowConfigExposed(),
    ArgoCDAnonymousAccess(),
    RabbitMQManagementExposed(),
    VaultUIExposed(),
    ConsulAPIExposed(),
    ElasticsearchClusterExposed(),
    ElasticsearchIndicesExposed(),
    PrometheusMetricsExposed(),
    K8sDashboardExposed(),
    PortainerAPIExposed(),
    SonarQubeAnonymousAccess(),
    HarborRegistryExposed(),
    NexusRepositoryExposed(),
    GitLabPublicProjectsExposed(),
    GiteaPublicReposExposed(),
    # ── Category 5: CMS-specific (13) ────────────────────────────────────
    WpDebugLog(),
    WpInstallExposed(),
    WpUserEnum(),
    WpReadmeExposed(),
    XmlrpcExposed(),
    DrupalChangelogExposed(),
    DrupalCron(),
    DrupalUpdatePhp(),
    MagentoLocalXml(),
    MagentoDownloader(),
    MagentoVersionDisclosure(),
    JoomlaConfigBackup(),
    JoomlaAdminVersion(),
    # ── Category 6: Cloud storage (8) ────────────────────────────────────
    S3BucketListing(),
    S3PolicyExposed(),
    AzureStorageContainerListing(),
    AzureBlobAnonAccess(),
    GcpStorageBucketListing(),
    GcpMetadataLeak(),
    CdnCacheBackend(),
    CloudfrontMisconfig(),
    # ── Category 7: AI/ML infrastructure (6) ─────────────────────────────
    OllamaExposed(),
    TritonExposed(),
    VllmExposed(),
    StableDiffusionExposed(),
    OpenWebUIExposed(),
    HuggingFaceSpacesMisconfig(),
    # ── Category 8: API documentation (5) ────────────────────────────────
    SwaggerUiExposed(),
    OpenApiJsonExposed(),
    GraphqlIntrospection(),
    GraphqlPlayground(),
    PostmanCollectionExposed(),
    # ── Category 9: Spring Boot Actuator (5) ─────────────────────────────
    ActuatorExposed(),
    ActuatorEnv(),
    ActuatorHeapdump(),
    ActuatorLoggers(),
    H2Console(),
    # ── Category 10: PHP/Apache server info (4) ──────────────────────────
    PhpinfoExposed(),
    ServerStatus(),
    ServerInfo(),
    ComposerFilesExposed(),
    # ── Category 11: Network service exposures (5) ───────────────────────
    RedisExposed(),
    MongoExposed(),
    ElasticsearchHttpExposed(),
    PostgresExposed(),
    MysqlExposed(),
    # ── Category 12: Nuclei CVE / community templates (1) ────────────────
    NucleiCveCheck(),
    # ── Category 13: Subdomain takeover (1) ──────────────────────────────
    SubdomainTakeover(),
    # ── Category 13: CORS misconfiguration (3) ───────────────────────────
    CorsWildcardWithCredentials(),
    CorsNullOrigin(),
    CorsPreflightWildcard(),
    # ── Category 13: Mail security (5) ───────────────────────────────────
    SpfMissing(),
    SpfWeak(),
    DmarcMissing(),
    DmarcWeak(),
    DkimNotFound(),
    # ── Category 13: DNS zone transfer (1) ───────────────────────────────
    ZoneTransferAllowed(),
    # ── Category 13: Content discovery (2) ───────────────────────────────
    RobotsSensitivePaths(),
    SitemapExposed(),
]


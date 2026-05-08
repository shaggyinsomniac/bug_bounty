"""
bounty.detect.admin_panels — Admin panel detection modules.

Re-exports all 26 detection classes for registration in REGISTERED_DETECTIONS.

Detection classes are fingerprint-gated: each implements ``applicable_to()``
gating on the relevant technology fingerprint, so they only run against assets
where the corresponding tech was detected.
"""

from __future__ import annotations

from bounty.detect.admin_panels.adminer import AdminerLoginExposed
from bounty.detect.admin_panels.airflow import (
    AirflowAnonymousAccess,
    AirflowConfigExposed,
)
from bounty.detect.admin_panels.argocd import ArgoCDAnonymousAccess
from bounty.detect.admin_panels.consul import ConsulAPIExposed
from bounty.detect.admin_panels.elasticsearch import (
    ElasticsearchClusterExposed,
    ElasticsearchIndicesExposed,
)
from bounty.detect.admin_panels.gitea import GiteaPublicReposExposed
from bounty.detect.admin_panels.gitlab import GitLabPublicProjectsExposed
from bounty.detect.admin_panels.grafana import (
    GrafanaAnonymousAccess,
    GrafanaSnapshotExposed,
)
from bounty.detect.admin_panels.harbor import HarborRegistryExposed
from bounty.detect.admin_panels.jenkins import (
    JenkinsAnonymousDashboard,
    JenkinsBuildHistoryExposed,
    JenkinsScriptConsole,
)
from bounty.detect.admin_panels.kibana import KibanaAnonymousAccess
from bounty.detect.admin_panels.kubernetes_dashboard import K8sDashboardExposed
from bounty.detect.admin_panels.nexus import NexusRepositoryExposed
from bounty.detect.admin_panels.phpmyadmin import PhpMyAdminLoginExposed
from bounty.detect.admin_panels.portainer import PortainerAPIExposed
from bounty.detect.admin_panels.prometheus import PrometheusMetricsExposed
from bounty.detect.admin_panels.rabbitmq import RabbitMQManagementExposed
from bounty.detect.admin_panels.sonarqube import SonarQubeAnonymousAccess
from bounty.detect.admin_panels.solr import SolrAdminConsole, SolrCoresExposed
from bounty.detect.admin_panels.vault import VaultUIExposed

__all__ = [
    "AdminerLoginExposed",
    "AirflowAnonymousAccess",
    "AirflowConfigExposed",
    "ArgoCDAnonymousAccess",
    "ConsulAPIExposed",
    "ElasticsearchClusterExposed",
    "ElasticsearchIndicesExposed",
    "GiteaPublicReposExposed",
    "GitLabPublicProjectsExposed",
    "GrafanaAnonymousAccess",
    "GrafanaSnapshotExposed",
    "HarborRegistryExposed",
    "JenkinsAnonymousDashboard",
    "JenkinsBuildHistoryExposed",
    "JenkinsScriptConsole",
    "KibanaAnonymousAccess",
    "K8sDashboardExposed",
    "NexusRepositoryExposed",
    "PhpMyAdminLoginExposed",
    "PortainerAPIExposed",
    "PrometheusMetricsExposed",
    "RabbitMQManagementExposed",
    "SonarQubeAnonymousAccess",
    "SolrAdminConsole",
    "SolrCoresExposed",
    "VaultUIExposed",
]


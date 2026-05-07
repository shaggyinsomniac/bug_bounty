"""
bounty.fingerprint.headers — Technology detection from HTTP response headers.

Pure function, no I/O.  All callers are responsible for filling ``asset_id``
on the returned results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bounty.models import FingerprintCategory, FingerprintResult


@dataclass(frozen=True)
class _HeaderRule:
    header: str        # lower-cased header name
    pattern: re.Pattern[str]
    tech: str
    category: FingerprintCategory
    confidence: int
    version_group: int = 0  # capture group index; 0 = no version


def _re(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


_RULES: list[_HeaderRule] = [
    # Server
    _HeaderRule("server", _re(r"nginx(?:/(\S+))?"), "nginx", "web-server", 90, 1),
    _HeaderRule("server", _re(r"apache(?:/(\S+))?"), "apache", "web-server", 90, 1),
    _HeaderRule("server", _re(r"Microsoft-IIS(?:/(\S+))?"), "iis", "web-server", 90, 1),
    _HeaderRule("server", _re(r"cloudflare"), "cloudflare", "cdn", 90),
    _HeaderRule("server", _re(r"AmazonS3"), "aws-s3", "other", 95),
    _HeaderRule("server", _re(r"Caddy"), "caddy", "web-server", 90),
    _HeaderRule("server", _re(r"gunicorn(?:/(\S+))?"), "gunicorn", "web-server", 90, 1),
    _HeaderRule("server", _re(r"uvicorn"), "uvicorn", "web-server", 85),
    _HeaderRule("server", _re(r"Werkzeug(?:/(\S+))?"), "werkzeug", "framework", 85, 1),
    _HeaderRule("server", _re(r"openresty"), "openresty", "web-server", 90),
    _HeaderRule("server", _re(r"lighttpd(?:/(\S+))?"), "lighttpd", "web-server", 90, 1),
    _HeaderRule("server", _re(r"LiteSpeed"), "litespeed", "web-server", 90),
    # X-Powered-By
    _HeaderRule("x-powered-by", _re(r"PHP(?:/(\S+))?"), "php", "language", 95, 1),
    _HeaderRule("x-powered-by", _re(r"ASP\.NET"), "asp.net", "framework", 90),
    _HeaderRule("x-powered-by", _re(r"Express"), "express", "framework", 90),
    _HeaderRule("x-powered-by", _re(r"Next\.js"), "nextjs", "framework", 90),
    _HeaderRule("x-powered-by", _re(r"Laravel"), "laravel", "framework", 90),
    # ASP.NET
    _HeaderRule("x-aspnet-version", _re(r"(\S+)"), "asp.net", "framework", 95, 1),
    _HeaderRule("x-aspnetmvc-version", _re(r"(\S+)"), "asp.net-mvc", "framework", 95, 1),
    # CMS / app
    _HeaderRule("x-generator", _re(r"Drupal\s+(\d+[\.\d]*)"), "drupal", "cms", 95, 1),
    _HeaderRule("x-drupal-cache", _re(r".*"), "drupal", "cms", 90),
    _HeaderRule("x-drupal-dynamic-cache", _re(r".*"), "drupal", "cms", 90),
    _HeaderRule("x-pingback", _re(r"xmlrpc\.php"), "wordpress", "cms", 80),
    _HeaderRule("x-jenkins", _re(r"(\S*)"), "jenkins", "other", 95, 1),
    _HeaderRule("x-magento-cache-control", _re(r".*"), "magento", "cms", 85),
    _HeaderRule("x-magento-tags", _re(r".*"), "magento", "cms", 85),
    _HeaderRule("x-shopify-stage", _re(r".*"), "shopify", "cms", 90),
    _HeaderRule("x-shopify-shop-id", _re(r".*"), "shopify", "cms", 90),
    _HeaderRule("x-confluence-request-time", _re(r".*"), "confluence", "other", 90),
    _HeaderRule("x-atlassian-token", _re(r".*"), "atlassian", "other", 80),
    _HeaderRule("x-github-request-id", _re(r".*"), "github", "other", 85),
    _HeaderRule("x-gitlab-meta", _re(r".*"), "gitlab", "other", 90),
    _HeaderRule("x-runtime", _re(r"(\d+\.\d+)"), "rails", "framework", 70, 1),
    # CDN
    _HeaderRule("cf-ray", _re(r".*"), "cloudflare", "cdn", 90),
    _HeaderRule("x-amz-cf-id", _re(r".*"), "cloudfront", "cdn", 95),
    _HeaderRule("x-amz-cf-pop", _re(r".*"), "cloudfront", "cdn", 95),
    _HeaderRule("x-akamai-transformed", _re(r".*"), "akamai", "cdn", 90),
    _HeaderRule("x-check-cacheable", _re(r".*"), "akamai", "cdn", 80),
    _HeaderRule("via", _re(r"fastly", ), "fastly", "cdn", 85),
    _HeaderRule("x-served-by", _re(r"cache-"), "fastly", "cdn", 80),
    _HeaderRule("x-timer", _re(r"S\d"), "fastly", "cdn", 80),
    _HeaderRule("x-varnish", _re(r"\d"), "varnish", "cdn", 85),
    _HeaderRule("x-sucuri-id", _re(r".*"), "sucuri", "waf", 90),
    # WAF
    _HeaderRule("x-waf-event-info", _re(r".*"), "imperva", "waf", 85),
    _HeaderRule("x-iinfo", _re(r".*"), "imperva", "waf", 85),
    _HeaderRule("x-datadome-request-id", _re(r".*"), "datadome", "waf", 90),
]


def parse_headers(headers: dict[str, str]) -> list[FingerprintResult]:
    """Detect technologies from HTTP response headers.

    Args:
        headers: HTTP response header dict (any case — normalised internally).

    Returns:
        List of ``FingerprintResult`` with ``asset_id=None``.
    """
    # Normalise to lowercase keys once
    norm: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    results: list[FingerprintResult] = []

    for rule in _RULES:
        value = norm.get(rule.header, "")
        if not value:
            continue
        m = rule.pattern.search(value)
        if not m:
            continue

        version: str | None = None
        if rule.version_group and m.lastindex is not None and rule.version_group <= m.lastindex:
            raw_ver = m.group(rule.version_group)
            version = raw_ver.strip() or None

        results.append(
            FingerprintResult(
                tech=rule.tech,
                version=version,
                category=rule.category,
                confidence=rule.confidence,
                evidence=f"{rule.header}: {value[:200]}",
            )
        )

    return results


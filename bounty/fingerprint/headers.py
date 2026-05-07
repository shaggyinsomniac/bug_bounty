"""
bounty.fingerprint.headers — Technology detection from HTTP response headers.

Pure function, no I/O.  All callers are responsible for filling ``asset_id``
on the returned results.

Evidence format (Principle 5): ``header:<name>=<value[:200]>``
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bounty.models import ConfidenceTier, FingerprintCategory, FingerprintResult


@dataclass(frozen=True)
class _HeaderRule:
    header: str                  # lower-cased header name
    pattern: re.Pattern[str]
    tech: str
    category: FingerprintCategory
    confidence: ConfidenceTier   # tier when version IS captured (or no version_group)
    version_group: int = 0       # capture group index; 0 = no version
    # Optional fallback tier used when version_group is set but the version
    # capture group did NOT match (header present but carries no version).
    confidence_no_version: ConfidenceTier | None = None


def _re(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


_RULES: list[_HeaderRule] = [
    # ── Server header ──────────────────────────────────────────────────────
    # nginx/X.Y → DEFINITIVE (version-bearing); naked "nginx" → STRONG
    _HeaderRule("server", _re(r"nginx(?:/(\S+))?"), "nginx", "web-server",
                "definitive", 1, "strong"),
    # Apache/X.Y → DEFINITIVE; naked → STRONG
    _HeaderRule("server", _re(r"apache(?:/(\S+))?"), "apache", "web-server",
                "definitive", 1, "strong"),
    # IIS/X.Y → DEFINITIVE; naked → STRONG
    _HeaderRule("server", _re(r"Microsoft-IIS(?:/(\S+))?"), "iis", "web-server",
                "definitive", 1, "strong"),
    # "cloudflare" is the complete Server header value on Cloudflare edges → STRONG
    _HeaderRule("server", _re(r"^cloudflare$"), "cloudflare", "cdn", "strong"),
    # AmazonS3 product name is unmistakable → DEFINITIVE
    _HeaderRule("server", _re(r"AmazonS3"), "aws-s3", "other", "definitive"),
    # Caddy — vendor-specific server, STRONG
    _HeaderRule("server", _re(r"Caddy"), "caddy", "web-server", "strong"),
    # gunicorn/X.Y → DEFINITIVE; naked → STRONG
    _HeaderRule("server", _re(r"gunicorn(?:/(\S+))?"), "gunicorn", "web-server",
                "definitive", 1, "strong"),
    # uvicorn — vendor-specific Python ASGI server, STRONG
    _HeaderRule("server", _re(r"uvicorn"), "uvicorn", "web-server", "strong"),
    # Werkzeug/X.Y → DEFINITIVE (Flask's built-in server); naked → STRONG
    _HeaderRule("server", _re(r"Werkzeug(?:/(\S+))?"), "werkzeug", "framework",
                "definitive", 1, "strong"),
    # OpenResty is nginx-based but a distinct product → STRONG
    _HeaderRule("server", _re(r"openresty"), "openresty", "web-server", "strong"),
    # lighttpd/X.Y → DEFINITIVE; naked → STRONG
    _HeaderRule("server", _re(r"lighttpd(?:/(\S+))?"), "lighttpd", "web-server",
                "definitive", 1, "strong"),
    # LiteSpeed — vendor-specific, STRONG
    _HeaderRule("server", _re(r"LiteSpeed"), "litespeed", "web-server", "strong"),

    # ── X-Powered-By ───────────────────────────────────────────────────────
    # PHP/X.Y → DEFINITIVE; naked "PHP" → STRONG
    _HeaderRule("x-powered-by", _re(r"PHP(?:/(\S+))?"), "php", "language",
                "definitive", 1, "strong"),
    # ASP.NET in X-Powered-By — vendor-specific no version, STRONG
    _HeaderRule("x-powered-by", _re(r"ASP\.NET"), "asp.net", "framework", "strong"),
    # Express, Next.js, Laravel in X-Powered-By — all vendor-specific, STRONG
    _HeaderRule("x-powered-by", _re(r"Express"), "express", "framework", "strong"),
    _HeaderRule("x-powered-by", _re(r"Next\.js"), "nextjs", "framework", "strong"),
    _HeaderRule("x-powered-by", _re(r"Laravel"), "laravel", "framework", "strong"),

    # ── ASP.NET version headers — always carry a version → DEFINITIVE ───────
    _HeaderRule("x-aspnet-version", _re(r"(\S+)"), "asp.net", "framework",
                "definitive", 1),
    _HeaderRule("x-aspnetmvc-version", _re(r"(\S+)"), "asp.net-mvc", "framework",
                "definitive", 1),

    # ── CMS / app-specific headers ─────────────────────────────────────────
    # X-Generator: Drupal X → version-bearing, unmistakable → DEFINITIVE
    _HeaderRule("x-generator", _re(r"Drupal\s+(\d+[\.\d]*)"), "drupal", "cms",
                "definitive", 1),
    # Drupal cache headers — vendor-specific → STRONG
    _HeaderRule("x-drupal-cache", _re(r".*"), "drupal", "cms", "strong"),
    _HeaderRule("x-drupal-dynamic-cache", _re(r".*"), "drupal", "cms", "strong"),
    # WordPress XML-RPC pingback path is WP-specific → STRONG
    _HeaderRule("x-pingback", _re(r"xmlrpc\.php"), "wordpress", "cms", "strong"),
    # Jenkins version in X-Jenkins header → DEFINITIVE
    _HeaderRule("x-jenkins", _re(r"(\S*)"), "jenkins", "other", "definitive", 1),
    # Magento proprietary cache headers → STRONG (vendor-specific, no version)
    _HeaderRule("x-magento-cache-control", _re(r".*"), "magento", "cms", "strong"),
    _HeaderRule("x-magento-tags", _re(r".*"), "magento", "cms", "strong"),
    # Shopify stage / shop-id are unmistakable vendor headers → DEFINITIVE
    _HeaderRule("x-shopify-stage", _re(r".*"), "shopify", "cms", "definitive"),
    _HeaderRule("x-shopify-shop-id", _re(r".*"), "shopify", "cms", "definitive"),
    # Atlassian / Confluence
    _HeaderRule("x-confluence-request-time", _re(r".*"), "confluence", "other", "strong"),
    # X-Atlassian-Token appears on multiple Atlassian products — WEAK (too broad)
    _HeaderRule("x-atlassian-token", _re(r".*"), "atlassian", "other", "weak"),
    # GitHub / GitLab — specific request-ID headers → STRONG
    _HeaderRule("x-github-request-id", _re(r".*"), "github", "other", "strong"),
    _HeaderRule("x-gitlab-meta", _re(r".*"), "gitlab", "other", "strong"),
    # X-Runtime is a Rack timing middleware header present in Rails, Sinatra,
    # Hanami, and any Rack-based app. Not unique → HINT (corroborates only).
    _HeaderRule("x-runtime", _re(r"(\d+\.\d+)"), "rails", "framework", "hint", 1),

    # ── CDN headers ────────────────────────────────────────────────────────
    # CF-Ray is a Cloudflare-exclusive edge-request ID → DEFINITIVE
    _HeaderRule("cf-ray", _re(r".*"), "cloudflare", "cdn", "definitive"),
    # CloudFront exclusive IDs → DEFINITIVE
    _HeaderRule("x-amz-cf-id", _re(r".*"), "cloudfront", "cdn", "definitive"),
    _HeaderRule("x-amz-cf-pop", _re(r".*"), "cloudfront", "cdn", "definitive"),
    # Akamai transformation header → DEFINITIVE (vendor-exclusive debug header)
    _HeaderRule("x-akamai-transformed", _re(r".*"), "akamai", "cdn", "definitive"),
    # X-Check-Cacheable is an Akamai config debug value → STRONG
    _HeaderRule("x-check-cacheable", _re(r".*"), "akamai", "cdn", "strong"),
    # Fastly via Via or X-Served-By with cache- prefix → STRONG
    _HeaderRule("via", _re(r"fastly"), "fastly", "cdn", "strong"),
    _HeaderRule("x-served-by", _re(r"cache-"), "fastly", "cdn", "strong"),
    # X-Timer is a Fastly timing sidecar — could be stripped/mimicked → WEAK
    _HeaderRule("x-timer", _re(r"S\d"), "fastly", "cdn", "weak"),
    # Varnish X-Varnish object-ID header → STRONG (specific numeric format)
    _HeaderRule("x-varnish", _re(r"\d"), "varnish", "cdn", "strong"),
    # Sucuri WAF exclusive ID → DEFINITIVE
    _HeaderRule("x-sucuri-id", _re(r".*"), "sucuri", "waf", "definitive"),

    # ── WAF headers ────────────────────────────────────────────────────────
    # Imperva/Incapsula WAF event headers → STRONG
    _HeaderRule("x-waf-event-info", _re(r".*"), "imperva", "waf", "strong"),
    _HeaderRule("x-iinfo", _re(r".*"), "imperva", "waf", "strong"),
    # DataDome bot-protection request ID → DEFINITIVE (vendor-exclusive)
    _HeaderRule("x-datadome-request-id", _re(r".*"), "datadome", "waf", "definitive"),
]


def parse_headers(headers: dict[str, str]) -> list[FingerprintResult]:
    """Detect technologies from HTTP response headers.

    Evidence format: ``header:<name>=<value>`` (Principle 5).

    Args:
        headers: HTTP response header dict (any case — normalised internally).

    Returns:
        List of ``FingerprintResult`` with ``asset_id=None``.
    """
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
            version = raw_ver.strip() if raw_ver else None

        # Select tier: use fallback when version was expected but absent
        if rule.confidence_no_version is not None and rule.version_group and version is None:
            conf: ConfidenceTier = rule.confidence_no_version
        else:
            conf = rule.confidence

        results.append(
            FingerprintResult(
                tech=rule.tech,
                version=version,
                category=rule.category,
                confidence=conf,
                evidence=f"header:{rule.header}={value[:200]}",
            )
        )

    return results


"""
bounty.fingerprint.cookies — Technology detection from Set-Cookie headers.

Pure function, no I/O.

Evidence format (Principle 5): ``cookie:<name>``
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bounty.models import ConfidenceTier, FingerprintCategory, FingerprintResult


@dataclass(frozen=True)
class _CookieRule:
    pattern: re.Pattern[str]   # matched against cookie name (case-sensitive)
    tech: str
    category: FingerprintCategory
    confidence: ConfidenceTier


def _re(p: str) -> re.Pattern[str]:
    return re.compile(p)


_RULES: list[_CookieRule] = [
    # PHP — session ID is generic PHP land, single indirect → WEAK
    _CookieRule(_re(r"^PHPSESSID$"), "php", "language", "weak"),
    # Java Servlet session — family-level signal ("java" but not which framework) → WEAK
    _CookieRule(_re(r"^JSESSIONID$"), "java", "language", "weak"),
    # ASP.NET — vendor-specific session cookie patterns → STRONG
    _CookieRule(_re(r"^ASP\.NET_SessionId$"), "asp.net", "framework", "strong"),
    _CookieRule(_re(r"^ASPSESSIONID"), "asp.net", "framework", "strong"),
    # Laravel session cookie is Laravel-exclusive → DEFINITIVE
    _CookieRule(_re(r"^laravel_session$"), "laravel", "framework", "definitive"),
    # Symfony redirect cookie — vendor-specific → STRONG
    _CookieRule(_re(r"^sf_redirect$"), "symfony", "framework", "strong"),
    # Rails _session_id — any Rack app can use this name → HINT (corroborates only)
    _CookieRule(_re(r"^_session_id$"), "rails", "framework", "hint"),
    # Express connect.sid — specific to Express/connect middleware → STRONG
    _CookieRule(_re(r"^connect\.sid$"), "express", "framework", "strong"),
    # WordPress — all WP-specific cookie namespaces → DEFINITIVE
    _CookieRule(_re(r"^wp-settings-"), "wordpress", "cms", "definitive"),
    _CookieRule(_re(r"^wordpress_logged_in_"), "wordpress", "cms", "definitive"),
    _CookieRule(_re(r"^wp-postpass_"), "wordpress", "cms", "definitive"),
    _CookieRule(_re(r"^wordpress_sec_"), "wordpress", "cms", "definitive"),
    # Drupal toolbar cookie and 32-hex session → STRONG (specific pattern)
    _CookieRule(_re(r"^Drupal\.toolbar\."), "drupal", "cms", "strong"),
    _CookieRule(_re(r"^SESS[0-9a-f]{32}$"), "drupal", "cms", "strong"),
    # Shopify — unmistakable vendor cookies → DEFINITIVE
    _CookieRule(_re(r"^SHOP_SESSION_TOKEN$"), "shopify", "cms", "definitive"),
    _CookieRule(_re(r"^_shopify_"), "shopify", "cms", "definitive"),
    # Cloudflare bot-management cookies — vendor-exclusive → DEFINITIVE
    _CookieRule(_re(r"^cf_clearance$"), "cloudflare", "cdn", "definitive"),
    _CookieRule(_re(r"^__cf_bm$"), "cloudflare", "cdn", "definitive"),
    # Imperva/Incapsula WAF cookies — vendor-exclusive → DEFINITIVE
    _CookieRule(_re(r"^incap_ses_"), "imperva", "waf", "definitive"),
    _CookieRule(_re(r"^visid_incap_"), "imperva", "waf", "definitive"),
    # AWS ELB stickiness cookies — vendor-specific → STRONG
    _CookieRule(_re(r"^AWSALB$"), "aws-elb", "other", "strong"),
    _CookieRule(_re(r"^AWSALBCORS$"), "aws-elb", "other", "strong"),
    # DataDome bot-protection cookie — vendor-exclusive → DEFINITIVE
    _CookieRule(_re(r"^datadome$"), "datadome", "waf", "definitive"),
    # Akamai UUID cookie → STRONG (vendor-specific but not unmistakable alone)
    _CookieRule(_re(r"^akm_uuid$"), "akamai", "cdn", "strong"),
    # F5 BigIP — BIGipServer prefix is well-known → STRONG
    _CookieRule(_re(r"^BIGipServer"), "f5-bigip", "waf", "strong"),
    # SERVERID is too generic across many load balancers → WEAK
    _CookieRule(_re(r"^SERVERID$"), "f5-bigip", "waf", "weak"),
    # Varnish-prefixed cookies — present in some Varnish configs but not exclusive → WEAK
    _CookieRule(_re(r"^varnish"), "varnish", "cdn", "weak"),
    # Sitecore analytics cookie — vendor-exclusive → DEFINITIVE
    _CookieRule(_re(r"^SC_ANALYTICS_GLOBAL_COOKIE$"), "sitecore", "cms", "definitive"),
]

# Django requires BOTH csrftoken AND sessionid  (checked separately below)
_DJANGO_CSRF = _re(r"^csrftoken$")
_DJANGO_SESSION = _re(r"^sessionid$")
# XSRF-TOKEN is used by Laravel, Angular, and many others — too ambiguous → HINT
_XSRF_TOKEN = _re(r"^XSRF-TOKEN$")


def _cookie_name(raw: str) -> str:
    """Extract the cookie name from a raw Set-Cookie header value."""
    return raw.split(";")[0].split("=")[0].strip()


def parse_cookies(set_cookie_headers: list[str]) -> list[FingerprintResult]:
    """Detect technologies from Set-Cookie header values.

    Evidence format: ``cookie:<name>`` (Principle 5).

    Args:
        set_cookie_headers: List of raw ``Set-Cookie`` header values.

    Returns:
        List of ``FingerprintResult`` with ``asset_id=None``.
    """
    names = [_cookie_name(h) for h in set_cookie_headers if h.strip()]
    name_set = set(names)
    results: list[FingerprintResult] = []

    for name in names:
        for rule in _RULES:
            if rule.pattern.match(name):
                results.append(
                    FingerprintResult(
                        tech=rule.tech,
                        category=rule.category,
                        confidence=rule.confidence,
                        evidence=f"cookie:{name}",
                    )
                )

    # Django: both csrftoken AND sessionid required → STRONG combined signal
    if any(_DJANGO_CSRF.match(n) for n in name_set) and any(
        _DJANGO_SESSION.match(n) for n in name_set
    ):
        results.append(
            FingerprintResult(
                tech="django",
                category="framework",
                confidence="strong",
                evidence="cookie:csrftoken+sessionid",
            )
        )

    # XSRF-TOKEN alone is ambiguous (Laravel / Angular / others) → HINT
    if any(_XSRF_TOKEN.match(n) for n in name_set):
        results.append(
            FingerprintResult(
                tech="laravel-or-angular",
                category="framework",
                confidence="hint",
                evidence="cookie:XSRF-TOKEN",
            )
        )

    return results

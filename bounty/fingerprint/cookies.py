"""
bounty.fingerprint.cookies — Technology detection from Set-Cookie headers.

Pure function, no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bounty.models import FingerprintCategory, FingerprintResult


@dataclass(frozen=True)
class _CookieRule:
    pattern: re.Pattern[str]   # matched against **cookie name** (case-sensitive)
    tech: str
    category: FingerprintCategory
    confidence: int


def _re(p: str) -> re.Pattern[str]:
    return re.compile(p)


_RULES: list[_CookieRule] = [
    # PHP
    _CookieRule(_re(r"^PHPSESSID$"), "php", "language", 70),
    # Java / J2EE
    _CookieRule(_re(r"^JSESSIONID$"), "java", "language", 60),
    # ASP.NET
    _CookieRule(_re(r"^ASP\.NET_SessionId$"), "asp.net", "framework", 80),
    _CookieRule(_re(r"^ASPSESSIONID"), "asp.net", "framework", 80),
    # Laravel
    _CookieRule(_re(r"^laravel_session$"), "laravel", "framework", 90),
    # Symfony
    _CookieRule(_re(r"^sf_redirect$"), "symfony", "framework", 80),
    # Rails
    _CookieRule(_re(r"^_session_id$"), "rails", "framework", 50),
    # Express / Node
    _CookieRule(_re(r"^connect\.sid$"), "express", "framework", 80),
    # WordPress
    _CookieRule(_re(r"^wp-settings-"), "wordpress", "cms", 90),
    _CookieRule(_re(r"^wordpress_logged_in_"), "wordpress", "cms", 90),
    _CookieRule(_re(r"^wp-postpass_"), "wordpress", "cms", 90),
    _CookieRule(_re(r"^wordpress_sec_"), "wordpress", "cms", 85),
    # Drupal
    _CookieRule(_re(r"^Drupal\.toolbar\."), "drupal", "cms", 85),
    _CookieRule(_re(r"^SESS[0-9a-f]{32}$"), "drupal", "cms", 85),  # Drupal session pattern
    # Shopify
    _CookieRule(_re(r"^SHOP_SESSION_TOKEN$"), "shopify", "cms", 90),
    _CookieRule(_re(r"^_shopify_"), "shopify", "cms", 85),
    # Cloudflare
    _CookieRule(_re(r"^cf_clearance$"), "cloudflare", "cdn", 90),
    _CookieRule(_re(r"^__cf_bm$"), "cloudflare", "cdn", 90),
    # Imperva / Incapsula
    _CookieRule(_re(r"^incap_ses_"), "imperva", "waf", 90),
    _CookieRule(_re(r"^visid_incap_"), "imperva", "waf", 90),
    # AWS
    _CookieRule(_re(r"^AWSALB$"), "aws-elb", "other", 70),
    _CookieRule(_re(r"^AWSALBCORS$"), "aws-elb", "other", 70),
    # DataDome
    _CookieRule(_re(r"^datadome$"), "datadome", "waf", 90),
    # Akamai
    _CookieRule(_re(r"^akm_uuid$"), "akamai", "cdn", 85),
    # F5 BigIP
    _CookieRule(_re(r"^BIGipServer"), "f5-bigip", "waf", 85),
    _CookieRule(_re(r"^SERVERID$"), "f5-bigip", "waf", 75),
    # Varnish
    _CookieRule(_re(r"^varnish"), "varnish", "cdn", 75),
    # Sitecore
    _CookieRule(_re(r"^SC_ANALYTICS_GLOBAL_COOKIE$"), "sitecore", "cms", 85),
]

# Django requires BOTH csrftoken AND sessionid  (checked separately below)
_DJANGO_CSRF = _re(r"^csrftoken$")
_DJANGO_SESSION = _re(r"^sessionid$")
# Generic XSRF-TOKEN (lower confidence without framework context)
_XSRF_TOKEN = _re(r"^XSRF-TOKEN$")


def _cookie_name(raw: str) -> str:
    """Extract the cookie name from a raw Set-Cookie header value."""
    return raw.split(";")[0].split("=")[0].strip()


def parse_cookies(set_cookie_headers: list[str]) -> list[FingerprintResult]:
    """Detect technologies from Set-Cookie header values.

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
                        evidence=f"cookie: {name}",
                    )
                )

    # Django: both csrftoken AND sessionid required
    if any(_DJANGO_CSRF.match(n) for n in name_set) and any(
        _DJANGO_SESSION.match(n) for n in name_set
    ):
        results.append(
            FingerprintResult(
                tech="django",
                category="framework",
                confidence=85,
                evidence="cookies: csrftoken + sessionid",
            )
        )

    # XSRF-TOKEN alone is ambiguous (Laravel / Angular / others)
    if any(_XSRF_TOKEN.match(n) for n in name_set):
        results.append(
            FingerprintResult(
                tech="laravel-or-angular",
                category="framework",
                confidence=50,
                evidence="cookie: XSRF-TOKEN",
            )
        )

    return results


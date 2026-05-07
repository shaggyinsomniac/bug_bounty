"""
bounty.fingerprint.body — Technology detection from HTML response bodies.

Pure function, no I/O.  Uses BeautifulSoup + lxml for parsing.
Capped at 512 KB to avoid memory pressure on large documents.

Evidence format (Principle 5): ``body:<source>=<value>``, ``meta:generator=<value>``, ``body:path=…``, ``body:class=…``, ``body:script=…``, ``body:title=…``, ``body:comment=…``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from bounty.models import FingerprintResult

if TYPE_CHECKING:
    pass

_CAP_BYTES = 512 * 1024  # 512 KB

# ── Path-based patterns (src/href in link/script tags) ────────────────────
# (path_fragment, tech, category, confidence_tier)
_PATH_RULES: list[tuple[str, str, str, str]] = [
    ("/wp-content/", "wordpress", "cms", "strong"),
    ("/wp-includes/", "wordpress", "cms", "strong"),
    ("/sites/all/", "drupal", "cms", "strong"),
    ("/sites/default/", "drupal", "cms", "strong"),
    ("/media/jui/", "joomla", "cms", "strong"),
    ("/skin/frontend/", "magento", "cms", "strong"),   # Magento 1.x CDN path
    ("/typo3/", "typo3", "cms", "strong"),
    ("/umbraco/", "umbraco", "cms", "strong"),
    ("/_next/static/", "nextjs", "framework", "definitive"),  # Next.js chunk CDN path
    ("/_nuxt/", "nuxt", "framework", "definitive"),           # Nuxt chunk CDN path
    ("/static/admin/", "django", "framework", "weak"),        # Django admin static
    ("/themes/shopify/", "shopify", "cms", "strong"),
]

# ── Title-based admin panel signals ───────────────────────────────────────
# (substring, tech, confidence_tier)  — case-insensitive
_TITLE_RULES: list[tuple[str, str, str]] = [
    # Default server pages — STRONG (specific page text)
    ("welcome to nginx", "nginx-default-page", "strong"),
    ("apache2 ubuntu default page", "apache-default-page", "strong"),
    # "It works!" is the Apache default but too short to be unambiguous → WEAK
    ("it works!", "apache-default-page", "weak"),
    ("iis windows server", "iis-default-page", "strong"),
    ("iis10", "iis-default-page", "strong"),
    ("internet information services", "iis-default-page", "strong"),
    # Directory listing format is very specific → DEFINITIVE
    ("index of /", "directory-listing", "definitive"),
    # phpinfo() in title is unambiguous → DEFINITIVE
    ("phpinfo()", "phpinfo-exposed", "definitive"),
    # Admin panels — titles are modifiable but these are very specific → STRONG
    ("jenkins", "jenkins", "strong"),
    ("dashboard [jenkins]", "jenkins", "strong"),
    ("grafana", "grafana", "strong"),
    ("kibana", "kibana", "strong"),
    ("phpmyadmin", "phpmyadmin", "strong"),
    ("adminer", "adminer", "strong"),
    ("confluence", "confluence", "strong"),
    ("jira", "jira", "strong"),
    ("gitlab", "gitlab", "strong"),
    ("gitea", "gitea", "strong"),
    ("argo cd", "argocd", "strong"),
    ("harbor", "harbor", "strong"),
    ("nexus repository", "nexus", "strong"),
    ("sonarqube", "sonarqube", "strong"),
    ("rabbitmq management", "rabbitmq-mgmt", "strong"),
    ("apache spark", "spark", "strong"),
    ("apache airflow", "airflow", "strong"),
    ("apache solr", "solr", "strong"),
    ("consul", "consul", "strong"),
    ("kubernetes dashboard", "k8s-dashboard", "strong"),
    ("portainer", "portainer", "strong"),
    ("rancher", "rancher", "strong"),
    ("zabbix", "zabbix", "strong"),
    ("nagios", "nagios", "strong"),
    ("prometheus", "prometheus", "strong"),
    ("mattermost", "mattermost", "strong"),
    ("rocket.chat", "rocketchat", "strong"),
    ("discourse", "discourse", "strong"),
    ("webmin", "webmin", "strong"),
    ("cpanel", "cpanel", "strong"),
    ("plesk", "plesk", "strong"),
    # "drone" alone is too generic → WEAK
    ("drone", "drone-ci", "weak"),
    ("spinnaker", "spinnaker", "strong"),
]

# ── Regex patterns for meta generator tag ─────────────────────────────────────
_GENERATOR_RE = re.compile(
    r"<meta\s[^>]*name=[\"']generator[\"']\s[^>]*content=[\"']([^\"'<]+)",
    re.IGNORECASE,
)
_GENERATOR_TECHS: dict[str, tuple[str, str]] = {
    "wordpress": ("wordpress", "cms"),
    "drupal": ("drupal", "cms"),
    "joomla": ("joomla", "cms"),
    "hugo": ("hugo", "framework"),
    "jekyll": ("jekyll", "framework"),
    "ghost": ("ghost", "cms"),
    "wix": ("wix", "cms"),
    "squarespace": ("squarespace", "cms"),
    "typo3": ("typo3", "cms"),
    "umbraco": ("umbraco", "cms"),
    "shopify": ("shopify", "cms"),
    "magento": ("magento", "cms"),
    "prestashop": ("prestashop", "cms"),
    "moodle": ("moodle", "cms"),
    "zendesk": ("zendesk", "other"),
}
_VERSION_RE = re.compile(r"(\d+[\.\d]*)")


def _decode_body(body: bytes) -> str:
    """Decode response bytes to string with best-effort charset detection."""
    try:
        import chardet
        detected = chardet.detect(body[:4096])
        enc = detected.get("encoding") or "utf-8"
    except Exception:  # noqa: BLE001
        enc = "utf-8"
    return body.decode(enc, errors="replace")


def parse_body(body: bytes, content_type: str | None, url: str) -> list[FingerprintResult]:
    """Detect technologies from an HTML response body.

    Evidence format: structured ``source:key=value`` per Principle 5.

    Args:
        body: Raw response bytes.
        content_type: Value of the Content-Type response header (may be None).
        url: The probed URL (used for context only).

    Returns:
        List of ``FingerprintResult`` with ``asset_id=None``.
    """
    ct = (content_type or "").lower()
    if ct and "html" not in ct and "text" not in ct:
        return []

    if not body:
        return []

    capped = body[:_CAP_BYTES]
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(capped, "lxml")
    except Exception:  # noqa: BLE001
        soup = None

    results: list[FingerprintResult] = []
    text = _decode_body(capped)

    # ── meta name="generator" → version-bearing → DEFINITIVE ─────────────
    m = _GENERATOR_RE.search(text)
    if m:
        gen_value = m.group(1).strip()
        gen_lower = gen_value.lower()
        for key, (tech, cat) in _GENERATOR_TECHS.items():
            if key in gen_lower:
                ver_m = _VERSION_RE.search(gen_value)
                results.append(
                    FingerprintResult(
                        tech=tech,
                        version=ver_m.group(1) if ver_m else None,
                        category=cat,  # type: ignore[arg-type]
                        confidence="definitive",
                        evidence=f"meta:generator={gen_value[:200]}",
                    )
                )
                break

    # ── Comment: Powered by Shopify → STRONG ──────────────────────────────
    if "powered by shopify" in text.lower():
        results.append(
            FingerprintResult(
                tech="shopify",
                category="cms",
                confidence="strong",
                evidence="body:comment=powered-by-shopify",
            )
        )

    # ── Path patterns in src/href attributes ───────────────────────────────
    if soup is not None:
        url_attrs: list[str] = []
        for tag in soup.find_all(["script", "link", "img", "a"]):
            for attr in ("src", "href", "data-src"):
                val = tag.get(attr, "")
                if val:
                    url_attrs.append(str(val))
    else:
        url_attrs = re.findall(r'(?:src|href)=["\']([^"\']+)', text)

    for path in url_attrs:
        for fragment, tech, cat, conf in _PATH_RULES:
            if fragment in path:
                results.append(
                    FingerprintResult(
                        tech=tech,
                        category=cat,  # type: ignore[arg-type]
                        confidence=conf,  # type: ignore[arg-type]
                        evidence=f"body:path={path[:200]}",
                    )
                )
                break

    # ── Zendesk detection (runs BEFORE body-class / script signals) ────────
    # Principle 3: when Zendesk is detected at STRONG+, suppress rails-hotwire.
    zendesk_detected = False
    if soup is not None:
        for tag in soup.find_all(["script", "link"]):
            for attr in ("src", "href"):
                val = str(tag.get(attr, ""))
                if "zendesk.com" in val:
                    zendesk_detected = True
                    break
            if zendesk_detected:
                break
    # Also check meta generator or zd-zopim class (handled by meta:generator above, but catch others)
    if not zendesk_detected and "zd-zopim" in text:
        zendesk_detected = True
    if zendesk_detected:
        # Only add if not already added by meta:generator
        if not any(r.tech == "zendesk" for r in results):
            results.append(
                FingerprintResult(
                    tech="zendesk",
                    category="other",
                    confidence="strong",
                    evidence="body:zendesk-src",
                )
            )

    # ── Body class attribute ────────────────────────────────────────────────
    if soup is not None:
        body_tag = soup.find("body")
        if body_tag:
            raw_class = body_tag.get("class")
            if isinstance(raw_class, list):
                cls = " ".join(str(c) for c in raw_class)
            else:
                cls = str(raw_class) if raw_class else ""
            # WordPress-specific body class prefix → STRONG
            if "wp-" in cls:
                results.append(
                    FingerprintResult(
                        tech="wordpress",
                        category="cms",
                        confidence="strong",
                        evidence=f"body:class={cls[:200]}",
                    )
                )
            # Require genuinely Magento-specific class prefixes.
            # "cms-page" and "page-" are also emitted by Drupal/other CMSs and
            # are intentionally excluded. See Phase 3.1 fix.
            if any(x in cls for x in ("catalog-product", "catalog-category", "checkout-")):
                results.append(
                    FingerprintResult(
                        tech="magento",
                        category="cms",
                        confidence="weak",
                        evidence=f"body:class={cls[:200]}",
                    )
                )

    # ── Script / data signals ──────────────────────────────────────────────
    # (signal, tech, category, tier)
    script_signals: list[tuple[str, str, str, str]] = [
        ("__NEXT_DATA__", "nextjs", "framework", "definitive"),   # Next.js inline data blob
        ("__NUXT__", "nuxt", "framework", "definitive"),          # Nuxt inline state
        ("data-react-helmet", "react", "framework", "strong"),    # React-Helmet specific attr
        # window.__REACT_DEVTOOLS appears in development builds, stripped in prod → HINT
        ("window.__REACT_DEVTOOLS", "react", "framework", "hint"),
        ("ng-app", "angularjs", "framework", "strong"),           # AngularJS directive
        ("ng-controller", "angularjs", "framework", "strong"),
        # Hotwire/Turbo markers — present on Zendesk, GitHub, and others that host
        # Rails internally. Not reliable for fingerprinting the *asset* as a Rails app.
        # Suppress when Zendesk already detected (Principle 3 applied in body parser).
        ("data-turbo", "rails-hotwire", "framework", "hint"),
        ("action-cable-meta", "rails-hotwire", "framework", "hint"),
    ]
    for signal, tech, cat, conf in script_signals:
        # Principle 3 early exit: suppress rails-hotwire when Zendesk detected
        if tech == "rails-hotwire" and zendesk_detected:
            continue
        if signal in text:
            results.append(
                FingerprintResult(
                    tech=tech,
                    category=cat,  # type: ignore[arg-type]
                    confidence=conf,  # type: ignore[arg-type]
                    evidence=f"body:script={signal}",
                )
            )

    # ── Title-based detection ─────────────────────────────────────────────
    title_text = ""
    if soup is not None:
        title_tag = soup.find("title")
        if title_tag:
            title_text = title_tag.get_text(strip=True).lower()
    else:
        t_m = re.search(r"<title[^>]*>([^<]{1,300})</title>", text, re.IGNORECASE)
        if t_m:
            title_text = t_m.group(1).strip().lower()

    if title_text:
        for substring, tech, conf in _TITLE_RULES:
            if substring in title_text:
                results.append(
                    FingerprintResult(
                        tech=tech,
                        category="other",
                        confidence=conf,  # type: ignore[arg-type]
                        evidence=f"body:title={title_text[:200]}",
                    )
                )

    return results


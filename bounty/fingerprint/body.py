"""
bounty.fingerprint.body — Technology detection from HTML response bodies.

Pure function, no I/O.  Uses BeautifulSoup + lxml for parsing.
Capped at 512 KB to avoid memory pressure on large documents.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from bounty.models import FingerprintResult

if TYPE_CHECKING:
    pass

_CAP_BYTES = 512 * 1024  # 512 KB

# ── Path-based patterns (src/href in link/script tags) ────────────────────
_PATH_RULES: list[tuple[str, str, str, int]] = [
    # (path_fragment, tech, category, confidence)
    ("/wp-content/", "wordpress", "cms", 80),
    ("/wp-includes/", "wordpress", "cms", 80),
    ("/sites/all/", "drupal", "cms", 80),
    ("/sites/default/", "drupal", "cms", 80),
    ("/media/jui/", "joomla", "cms", 80),
    ("/skin/frontend/", "magento", "cms", 80),
    ("/typo3/", "typo3", "cms", 80),
    ("/umbraco/", "umbraco", "cms", 80),
    ("/_next/static/", "nextjs", "framework", 90),
    ("/_nuxt/", "nuxt", "framework", 90),
    ("/static/admin/", "django", "framework", 75),
    ("/themes/shopify/", "shopify", "cms", 80),
]

# ── Title-based admin panel signals ───────────────────────────────────────
_TITLE_RULES: list[tuple[str, str, int]] = [
    # (substring, tech, confidence)  — case-insensitive
    ("welcome to nginx", "nginx-default-page", 85),
    ("apache2 ubuntu default page", "apache-default-page", 85),
    ("it works!", "apache-default-page", 85),
    ("iis windows server", "iis-default-page", 85),
    ("iis10", "iis-default-page", 85),
    ("internet information services", "iis-default-page", 85),
    ("index of /", "directory-listing", 95),
    ("phpinfo()", "phpinfo-exposed", 100),
    ("jenkins", "jenkins", 95),
    ("dashboard [jenkins]", "jenkins", 95),
    ("grafana", "grafana", 95),
    ("kibana", "kibana", 95),
    ("phpmyadmin", "phpmyadmin", 95),
    ("adminer", "adminer", 95),
    ("confluence", "confluence", 90),
    ("jira", "jira", 90),
    ("gitlab", "gitlab", 90),
    ("gitea", "gitea", 90),
    ("argo cd", "argocd", 95),
    ("harbor", "harbor", 95),
    ("nexus repository", "nexus", 95),
    ("sonarqube", "sonarqube", 90),
    ("rabbitmq management", "rabbitmq-mgmt", 95),
    ("apache spark", "spark", 95),
    ("apache airflow", "airflow", 95),
    ("apache solr", "solr", 95),
    ("consul", "consul", 90),
    ("kubernetes dashboard", "k8s-dashboard", 95),
    ("portainer", "portainer", 95),
    ("rancher", "rancher", 90),
    ("zabbix", "zabbix", 90),
    ("nagios", "nagios", 90),
    ("prometheus", "prometheus", 90),
    ("mattermost", "mattermost", 85),
    ("rocket.chat", "rocketchat", 85),
    ("discourse", "discourse", 85),
    ("webmin", "webmin", 90),
    ("cpanel", "cpanel", 90),
    ("plesk", "plesk", 90),
    ("drone", "drone-ci", 90),
    ("spinnaker", "spinnaker", 90),
]

# ── Regex patterns for meta generator tag ─────────────────────────────────────
_GENERATOR_RE = re.compile(r"<meta\s[^>]*name=[\"']generator[\"']\s[^>]*content=[\"']([^\"'<]+)", re.IGNORECASE)
_GENERATOR_TECHS: dict[str, tuple[str, str]] = {
    # (key_lower, (tech, category))
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
}
_VERSION_RE = re.compile(r"(\d+[\.\d]*)")


def _decode_body(body: bytes) -> str:
    """Decode response bytes to string with best-effort charset detection."""
    # Try chardet first, then fall back to utf-8 with replacement
    try:
        import chardet
        detected = chardet.detect(body[:4096])
        enc = detected.get("encoding") or "utf-8"
    except Exception:  # noqa: BLE001
        enc = "utf-8"
    return body.decode(enc, errors="replace")


def parse_body(body: bytes, content_type: str | None, url: str) -> list[FingerprintResult]:
    """Detect technologies from an HTML response body.

    Args:
        body: Raw response bytes.
        content_type: Value of the Content-Type response header (may be None).
        url: The probed URL (used for context only).

    Returns:
        List of ``FingerprintResult`` with ``asset_id=None``.
    """
    ct = (content_type or "").lower()
    # Only skip if we *know* this isn't HTML/text (e.g. image/png, application/json).
    # Treat empty/None content_type as HTML (permissive default — many CDNs strip it).
    if ct and "html" not in ct and "text" not in ct:
        return []

    if not body:
        return []

    capped = body[:_CAP_BYTES]
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(capped, "lxml")
    except Exception:  # noqa: BLE001
        # Fall back to raw text scanning if lxml fails
        soup = None

    results: list[FingerprintResult] = []
    text = _decode_body(capped)

    # ── meta name="generator" ─────────────────────────────────────────────
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
                        confidence=95,
                        evidence=f"meta generator: {gen_value[:200]}",
                    )
                )
                break

    # ── Comment: Powered by Shopify ────────────────────────────────────────
    if "powered by shopify" in text.lower():
        results.append(
            FingerprintResult(
                tech="shopify",
                category="cms",
                confidence=80,
                evidence="comment: Powered by Shopify",
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
        # Fallback: crude regex scan
        url_attrs = re.findall(r'(?:src|href)=["\']([^"\']+)', text)

    for path in url_attrs:
        for fragment, tech, cat, conf in _PATH_RULES:
            if fragment in path:
                results.append(
                    FingerprintResult(
                        tech=tech,
                        category=cat,  # type: ignore[arg-type]
                        confidence=conf,
                        evidence=f"path: {path[:200]}",
                    )
                )
                break

    # ── Zendesk detection (runs BEFORE body-class / script signals) ────────
    zendesk_detected = False
    if soup is not None:
        # Check script/link srcs for zendesk.com
        for tag in soup.find_all(["script", "link"]):
            for attr in ("src", "href"):
                val = str(tag.get(attr, ""))
                if "zendesk.com" in val:
                    zendesk_detected = True
                    break
            if zendesk_detected:
                break
    # Also check raw text for meta generator or body class
    if not zendesk_detected and (
        'name="generator"' in text.lower() and "zendesk" in text.lower()
    ):
        zendesk_detected = True
    if not zendesk_detected and "zd-zopim" in text:
        zendesk_detected = True
    if zendesk_detected:
        results.append(
            FingerprintResult(
                tech="zendesk",
                category="other",
                confidence=95,
                evidence="zendesk.com in script/link src, meta generator, or zd-zopim body class",
            )
        )

    # ── Body class attribute ────────────────────────────────────────────────
    if soup is not None:
        body_tag = soup.find("body")
        if body_tag:
            # Extract class attribute safely
            raw_class = body_tag.get("class")
            if isinstance(raw_class, list):
                cls = " ".join(str(c) for c in raw_class)
            else:
                cls = str(raw_class) if raw_class else ""
            if "wp-" in cls:
                results.append(
                    FingerprintResult(
                        tech="wordpress",
                        category="cms",
                        confidence=70,
                        evidence=f"body.class: {cls[:200]}",
                    )
                )
            # Require at least one genuinely Magento-specific class prefix.
            # "cms-page" and "page-" are also emitted by Drupal/other CMSs,
            # so they are intentionally excluded from this rule.
            if any(x in cls for x in ("catalog-product", "catalog-category", "checkout-")):
                results.append(
                    FingerprintResult(
                        tech="magento",
                        category="cms",
                        confidence=60,
                        evidence=f"body.class: {cls[:200]}",
                    )
                )

    # ── Script / data signals ──────────────────────────────────────────────
    script_signals: list[tuple[str, str, str, int]] = [
        ("__NEXT_DATA__", "nextjs", "framework", 95),
        ("__NUXT__", "nuxt", "framework", 95),
        ("data-react-helmet", "react", "framework", 80),
        ("window.__REACT_DEVTOOLS", "react", "framework", 80),
        ("ng-app", "angularjs", "framework", 80),
        ("ng-controller", "angularjs", "framework", 80),
        # Hotwire / ActionCable are Rails markers but also appear on Zendesk help-centres.
        # Lower confidence (50) and suppress entirely when Zendesk already detected.
        ("data-turbo", "rails-hotwire", "framework", 50),
        ("action-cable-meta", "rails-hotwire", "framework", 50),
    ]
    for signal, tech, cat, conf in script_signals:
        # Skip Rails-hotwire signals when we already know this is Zendesk.
        if tech == "rails-hotwire" and zendesk_detected:
            continue
        if signal in text:
            results.append(
                FingerprintResult(
                    tech=tech,
                    category=cat,  # type: ignore[arg-type]
                    confidence=conf,
                    evidence=f"script: {signal}",
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
                # Special case: Vault needs "sealed" in body for high confidence
                if tech == "vault" and "sealed" not in text.lower():
                    conf = 75
                results.append(
                    FingerprintResult(
                        tech=tech,
                        category="other",
                        confidence=conf,
                        evidence=f"title: {title_text[:200]}",
                    )
                )

    return results


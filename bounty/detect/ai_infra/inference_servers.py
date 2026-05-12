"""
bounty.detect.ai_infra.inference_servers — Exposed AI/ML inference service detections.

Seven detections:
- OllamaExposed             — /api/tags returns model list
- TritonExposed             — /v2/models returns Triton model repo
- VllmExposed               — /v1/models returns vLLM-hosted model list
- StableDiffusionExposed    — /sdapi/v1/options returns SD config
- OpenWebUIExposed          — Open WebUI /api/config accessible
- HuggingFaceSpacesMisconfig — HF Spaces datasets/models listing public
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.admin_panels._common import parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class OllamaExposed(Detection):
    """Ollama inference server exposes model list at /api/tags without auth."""

    id = "ai_infra.ollama.exposed"
    name = "Ollama Inference Server Exposed"
    category = "ai_infra_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("ai", "ollama", "llm", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/api/tags"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        if "models" not in data:
            return
        models = data["models"]
        if not isinstance(models, list):
            return

        model_names = [m.get("name", "") for m in models if isinstance(m, dict)]
        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Ollama inference server exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"An Ollama LLM inference server is publicly accessible without "
                f"authentication. It exposes {len(model_names)} model(s): "
                f"{', '.join(model_names[:5])}. "
                "Attackers can use compute resources and access private models."
            ),
            remediation=(
                "Bind Ollama to localhost only (OLLAMA_HOST=127.0.0.1). "
                "Add authentication via a reverse proxy (nginx/Caddy). "
                "Apply network-level firewall rules to restrict access."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class TritonExposed(Detection):
    """Triton Inference Server model repository exposed at /v2/models."""

    id = "ai_infra.triton.exposed"
    name = "Triton Inference Server Exposed"
    category = "ai_infra_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("ai", "triton", "nvidia", "model-serving", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/v2/models"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        # Triton returns {"models": [{"name": "...", "version": "..."}]}
        # or a JSON array directly
        is_triton = False
        if isinstance(data, dict) and "models" in data:
            is_triton = True
        elif isinstance(data, list):
            # Check first item has "name" and optional "version"
            if data and isinstance(data[0], dict) and "name" in data[0]:
                is_triton = True
        if not is_triton:
            # Also check for triton header
            headers = {k.lower(): v for k, v in pr.headers.items()}
            if "server" not in headers or "triton" not in headers.get("server", "").lower():
                return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Triton inference server exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "An NVIDIA Triton Inference Server is publicly accessible without "
                "authentication. Attackers can enumerate deployed models, make "
                "inference requests, and potentially exfiltrate model weights."
            ),
            remediation=(
                "Enable Triton's authentication mode. Place the server behind "
                "an authenticated reverse proxy. Restrict network access to "
                "trusted clients only."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class VllmExposed(Detection):
    """vLLM inference server exposes model list at /v1/models without auth."""

    id = "ai_infra.vllm.exposed"
    name = "vLLM Inference Server Exposed"
    category = "ai_infra_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("ai", "vllm", "llm", "openai-compatible", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/v1/models"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # OpenAI-compatible: {"object": "list", "data": [...]}
        if data.get("object") != "list" and "data" not in data:
            return
        models = data.get("data", [])
        if not isinstance(models, list):
            return

        model_ids = [m.get("id", "") for m in models if isinstance(m, dict)]
        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"vLLM inference server exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"A vLLM inference server is publicly accessible without authentication. "
                f"It exposes {len(model_ids)} model(s): {', '.join(model_ids[:5])}. "
                "Attackers can use the OpenAI-compatible API to make inference requests."
            ),
            remediation=(
                "Set the VLLM_API_KEY environment variable to require authentication. "
                "Restrict the server to localhost or an internal network. "
                "Add rate limiting and authentication via a reverse proxy."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class StableDiffusionExposed(Detection):
    """Stable Diffusion WebUI API exposed at /sdapi/v1/options without auth."""

    id = "ai_infra.stable_diffusion.exposed"
    name = "Stable Diffusion WebUI API Exposed"
    category = "ai_infra_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("ai", "stable-diffusion", "image-generation", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/sdapi/v1/options"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # SD WebUI options contains these typical keys
        sd_keys = ["sd_model_checkpoint", "sd_vae", "samples_filename_pattern",
                   "outdir_samples", "CLIP_stop_at_last_layers"]
        if not any(k in data for k in sd_keys):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Stable Diffusion WebUI API exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Stable Diffusion WebUI API is publicly accessible without "
                "authentication. Attackers can generate images using the server's "
                "compute resources and access the full configuration including model paths."
            ),
            remediation=(
                "Launch the WebUI with --api-auth flag to require authentication. "
                "Restrict access to localhost or internal networks. "
                "Add a reverse proxy with authentication."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class OpenWebUIExposed(Detection):
    """Open WebUI instance exposed without authentication at /api/config."""

    id = "ai_infra.openwebui.exposed"
    name = "Open WebUI Exposed"
    category = "ai_infra_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("ai", "openwebui", "llm-ui", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        # Check /api/config for Open WebUI
        path = "/api/config"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # Open WebUI config contains these keys
        owui_keys = ["WEBUI_NAME", "WEBUI_URL", "OLLAMA_BASE_URL",
                     "OPENAI_API_BASE_URL", "ENABLE_SIGNUP", "DEFAULT_MODELS",
                     "WEBUI_AUTH"]
        if not any(k in data for k in owui_keys):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Open WebUI exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "An Open WebUI instance (LLM chat UI) is publicly accessible. "
                "The /api/config endpoint reveals backend LLM configuration including "
                "API keys, model settings, and authentication state."
            ),
            remediation=(
                "Enable authentication in Open WebUI settings. "
                "Restrict access to trusted networks. "
                "Do not expose Open WebUI publicly without authentication."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class HuggingFaceSpacesMisconfig(Detection):
    """HuggingFace Space with publicly exposed dataset or model files."""

    id = "ai_infra.huggingface.spaces_misconfig"
    name = "HuggingFace Space Misconfiguration"
    category = "ai_infra_exposure"
    severity_default = 400
    cwe = "CWE-284"
    tags = ("ai", "huggingface", "ml-platform", "data-exposure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        # Only relevant for HuggingFace-hosted or self-hosted HF spaces
        return (
            "huggingface.co" in asset.host
            or "hf.space" in asset.host
            or "gradio" in asset.host
        )

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        # Check if the Space API files endpoint is open
        path = "/api/queue/status"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)

        # Also check for Gradio API docs exposure
        api_path = "/api"
        api_url = asset.url.rstrip("/") + api_path
        api_pr = await ctx.probe_fn(api_url)

        exposed = False
        exposed_url = url
        exposed_path = path

        if api_pr.status_code == 200:
            data = parse_json_body(api_pr)
            if isinstance(data, dict) and ("named_endpoints" in data or "unnamed_endpoints" in data):
                exposed = True
                exposed_url = api_url
                exposed_path = api_path

        if not exposed and pr.status_code == 200:
            data2 = parse_json_body(pr)
            if isinstance(data2, dict) and "queue_size" in data2:
                exposed = True

        if not exposed:
            return

        await ctx.capture_evidence(exposed_url, api_pr if exposed_path == api_path else pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{exposed_path}",
            title=f"HuggingFace Space API exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=exposed_url,
            path=exposed_path,
            description=(
                "A HuggingFace Space or Gradio application exposes its API "
                "without authentication. The /api endpoint reveals all available "
                "model endpoints and may allow arbitrary inference requests."
            ),
            remediation=(
                "Enable HuggingFace Space auth settings. "
                "Use Gradio's auth parameter to require login. "
                "Review Space visibility settings in HuggingFace Hub."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )



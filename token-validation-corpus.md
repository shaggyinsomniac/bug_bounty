# Comprehensive Token & Credential Validation Reference

Every entry: detection regex, validation method (read-only, cost-free where possible),
what success looks like, and severity hint.

**Validation rules for the system:**
1. Always use the cheapest, lowest-impact validation endpoint available.
2. Cache validation results — never validate the same token twice.
3. Capture the full validation request/response as evidence.
4. Mark the validation timestamp on the finding.
5. If a token validates as live, escalate immediately (Discord ping, top of queue).
6. Never use a token for anything beyond validation — no enumeration, no reads, no writes.
7. Some validations consume a tiny bit of the victim's quota (an API call). That's
   acceptable; document it in the report.

---

## CLOUD PROVIDERS (HIGHEST VALUE)

### AWS Access Key
- **Pattern**: `AKIA[0-9A-Z]{16}` (long-term), `ASIA[0-9A-Z]{16}` (temporary STS)
- **Paired secret**: 40-char base64 — `[A-Za-z0-9/+=]{40}` near the access key
- **Validation**: `sts:GetCallerIdentity` — no permissions required, free, returns 
  the account ID, ARN, and userid if key is live.
- **How**: `aws sts get-caller-identity` with the keys set in env, or use boto3:
  ```python
  import boto3
  client = boto3.client('sts', aws_access_key_id=key, aws_secret_access_key=secret)
  identity = client.get_caller_identity()
  ```
- **Success**: Returns JSON with `Account`, `Arn`, `UserId`.
- **Severity**: P0 if live. Even more critical if the ARN indicates `root` or `*Admin*` role.
- **Bonus enumeration (CAUTIOUSLY)**: After validation, try `iam:ListUsers`, 
  `iam:GetAccountSummary`, `s3:ListBuckets` — these are read-only and reveal blast 
  radius. Document each call in evidence.

### AWS Session Token
- **Pattern**: starts with `FwoGZXIvYXdzE` typically, ~200+ chars
- **Validation**: same as access key but include `aws_session_token`.

### AWS SES SMTP Credentials
- **Pattern**: SMTP user starts with `AKIA`, password is base64 derivative
- **Validation**: connect to SMTP endpoint, AUTH PLAIN, observe response.

### GCP Service Account JSON
- **Pattern**: JSON containing `"type": "service_account"`, `"private_key": "-----BEGIN PRIVATE KEY-----"`
- **Validation**: 
  ```python
  from google.oauth2 import service_account
  from googleapiclient.discovery import build
  creds = service_account.Credentials.from_service_account_info(json_data)
  # Try Cloud Resource Manager: list projects
  service = build('cloudresourcemanager', 'v1', credentials=creds)
  projects = service.projects().list().execute()
  ```
- **Success**: Returns project list (empty list still = valid creds).
- **Severity**: P0.

### GCP API Key
- **Pattern**: `AIza[0-9A-Za-z_-]{35}`
- **Validation**: `https://maps.googleapis.com/maps/api/geocode/json?latlng=0,0&key=<KEY>` 
  — returns `OK` if valid + has Maps API enabled, or `REQUEST_DENIED` with reason.
- **Alternative**: Try multiple Google APIs to find which are enabled.
- **Severity**: P2-P0 depending on enabled APIs. Maps API alone = $$ for victim 
  (high P2). Vision/Translate enabled = larger blast radius.

### Azure Storage Account Key
- **Pattern**: `DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<base64>;EndpointSuffix=core.windows.net`
- **Validation**: 
  ```python
  from azure.storage.blob import BlobServiceClient
  client = BlobServiceClient.from_connection_string(conn_str)
  containers = list(client.list_containers())
  ```
- **Severity**: P0.

### Azure Service Principal
- **Pattern**: tenant_id, client_id, client_secret triplet
- **Validation**: acquire token via `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`

### Azure SAS Token
- **Pattern**: `?sv=...&sig=...&se=...`
- **Validation**: HEAD request on the resource.

### DigitalOcean Personal Access Token
- **Pattern**: `dop_v1_[a-f0-9]{64}`
- **Validation**: `GET https://api.digitalocean.com/v2/account` with `Authorization: Bearer <token>`
- **Success**: 200 with account info.
- **Severity**: P1-P0.

### Linode API Token
- **Pattern**: `[a-f0-9]{64}` (generic, hard to detect alone — context-dependent)
- **Validation**: `GET https://api.linode.com/v4/profile`
- **Severity**: P1-P0.

### Vultr API Key
- **Pattern**: 36 chars uppercase alphanumeric
- **Validation**: `GET https://api.vultr.com/v2/account`

### Hetzner Cloud Token
- **Pattern**: 64 chars alphanumeric
- **Validation**: `GET https://api.hetzner.cloud/v1/servers`

### OVH API Key
- Multiple keys: application key + secret + consumer key.
- **Validation**: `GET https://api.ovh.com/1.0/me` with proper signing.

### Cloudflare API Token
- **Pattern**: 40-char alphanumeric token (newer), or global API key (37 hex)
- **Validation**: 
  - Token: `GET https://api.cloudflare.com/client/v4/user/tokens/verify` with Bearer.
  - Global key: `GET https://api.cloudflare.com/client/v4/user` with X-Auth-Email + X-Auth-Key.
- **Severity**: P1-P0.

### Cloudflare Origin CA Key
- **Pattern**: `v1.0-[a-f0-9]{171}`
- **Validation**: API call to origin CA endpoint.

### Fastly API Token
- **Pattern**: alphanumeric, no obvious prefix
- **Validation**: `GET https://api.fastly.com/current_user` with `Fastly-Key: <token>`

### Heroku API Key
- **Pattern**: UUID format
- **Validation**: `GET https://api.heroku.com/account` with Bearer + `Accept: application/vnd.heroku+json; version=3`

### Vercel Token
- **Pattern**: 24-char alphanumeric
- **Validation**: `GET https://api.vercel.com/v2/user` with Bearer.

### Netlify Token
- **Pattern**: 64-char hex
- **Validation**: `GET https://api.netlify.com/api/v1/user` with Bearer.

### Railway Token
- **Pattern**: UUID
- **Validation**: GraphQL query to railway.app API.

### Render API Key
- **Pattern**: `rnd_[A-Za-z0-9]{27}` (approximate)
- **Validation**: `GET https://api.render.com/v1/services` with Bearer.

### Fly.io Token
- **Pattern**: `fo1_[A-Za-z0-9_-]+`
- **Validation**: `GET https://api.fly.io/graphql` user query.

### Scaleway Token
- **Pattern**: UUID
- **Validation**: `GET https://api.scaleway.com/account/v2/projects` with `X-Auth-Token`.

### IBM Cloud API Key
- **Pattern**: 44-char alphanumeric
- **Validation**: token exchange against IAM.

### Alibaba Cloud Access Key
- **Pattern**: `LTAI[A-Za-z0-9]{16,20}`
- **Validation**: STS-like endpoint.

---

## VERSION CONTROL & DEV PLATFORMS

### GitHub Personal Access Token (Classic)
- **Pattern**: `ghp_[A-Za-z0-9]{36}`
- **Validation**: `GET https://api.github.com/user` with `Authorization: token <PAT>`
- **Success**: 200 with user JSON.
- **Bonus**: Check scopes from `X-OAuth-Scopes` response header — `repo` scope = full repo access including private.
- **Severity**: P1-P0.

### GitHub Fine-Grained PAT
- **Pattern**: `github_pat_[A-Za-z0-9_]{80,}`
- **Validation**: same.

### GitHub OAuth Token
- **Pattern**: `gho_[A-Za-z0-9]{36}`

### GitHub User Access Token
- **Pattern**: `ghu_[A-Za-z0-9]{36}`

### GitHub Server Token (App)
- **Pattern**: `ghs_[A-Za-z0-9]{36}`

### GitHub Refresh Token
- **Pattern**: `ghr_[A-Za-z0-9]{36}`

### GitHub App Private Key (PEM)
- **Pattern**: `-----BEGIN RSA PRIVATE KEY-----` near GitHub App context
- **Validation**: generate JWT, exchange for installation token.

### GitLab Personal Access Token
- **Pattern**: `glpat-[A-Za-z0-9_-]{20}`
- **Validation**: `GET https://gitlab.com/api/v4/user` with `PRIVATE-TOKEN` header.

### GitLab Pipeline Trigger Token
- **Pattern**: `glptt-[a-f0-9]{40}`
- **Validation**: trigger pipeline endpoint (CAUTIOUS — would actually trigger; 
  use the validate-only check instead: `GET /api/v4/projects/<id>/triggers`).

### GitLab CI Job Token
- **Pattern**: `glcbt-` prefix.

### GitLab Runner Registration Token
- **Pattern**: `GR1348941...`
- **Validation**: `POST /api/v4/runners` with token (creates a runner — CAUTIOUS, 
  prefer just identifying as found).

### GitLab Deploy Token
- **Pattern**: `gldt-[A-Za-z0-9_-]{20}`

### Bitbucket App Password
- **Pattern**: 20-char alphanumeric
- **Validation**: `GET https://api.bitbucket.org/2.0/user` with Basic auth.

### Bitbucket Access Token
- **Pattern**: ATBB-prefixed

### Atlassian API Token
- **Pattern**: 24-char alphanumeric (no fixed prefix)
- **Validation**: `GET https://<your-domain>.atlassian.net/rest/api/3/myself` with Basic auth (email:token).

### Jira Cloud Token
- Same as Atlassian.

### Jira Server Personal Access Token
- **Pattern**: alphanumeric, often 24-44 chars
- **Validation**: `GET <jira>/rest/api/2/myself`.

### Sourcegraph Access Token
- **Pattern**: `sgp_[a-f0-9]{40}`
- **Validation**: GraphQL `currentUser` query.

### Gitea Access Token
- **Pattern**: 40-char hex
- **Validation**: `GET <gitea>/api/v1/user`.

### Codeberg / Forgejo
- Same shape as Gitea.

---

## PACKAGE REGISTRIES

### NPM Token
- **Pattern**: `npm_[A-Za-z0-9]{36}`
- **Validation**: `GET https://registry.npmjs.org/-/whoami` with Bearer.
- **Severity**: P1 (publish access to packages = supply chain risk).

### NPM Legacy Token
- **Pattern**: in `.npmrc` as `_authToken=<base64>` or `_auth=<base64>`
- **Validation**: same whoami endpoint.

### PyPI Token
- **Pattern**: `pypi-AgEIcHlwaS5vcmc...` (base64-ish, very long)
- **Validation**: `POST https://upload.pypi.org/legacy/` with Basic auth `__token__:<token>` 
  and a deliberately invalid form — observe whether auth passes (401 vs 400).
- **Severity**: P1.

### TestPyPI Token
- **Pattern**: same shape, different URL.

### RubyGems API Key
- **Pattern**: 48-char hex
- **Validation**: `GET https://rubygems.org/api/v1/profile/me.json` with `Authorization` header.

### Crates.io Token
- **Pattern**: 32-char alphanumeric
- **Validation**: `GET https://crates.io/api/v1/me` with `Authorization`.

### Maven Central Token
- Username + token in settings.xml.
- **Validation**: portal API.

### Docker Hub Personal Access Token
- **Pattern**: UUID
- **Validation**: 
  ```
  POST https://hub.docker.com/v2/users/login
  Body: {"username":"<u>","password":"<token>"}
  ```
  Returns JWT if valid.
- **Severity**: P1.

### Docker Hub Password (in .docker/config.json)
- **Pattern**: base64 in `auths.<registry>.auth`
- **Validation**: same login flow.

### GitHub Container Registry (ghcr.io)
- Uses GitHub PAT — same as GitHub PAT validation.

### GitLab Container Registry
- Uses GitLab PAT.

### Quay.io Token
- **Pattern**: alphanumeric
- **Validation**: `GET https://quay.io/api/v1/user/` with Bearer.

### JFrog Artifactory Token
- **Validation**: `GET <artifactory>/api/system/ping` then user info.

### Sonatype Nexus Token
- Similar.

### Snyk API Token
- **Pattern**: UUID
- **Validation**: `GET https://api.snyk.io/v1/user/me` with `Authorization: token <token>`.

---

## PAYMENT PROCESSORS (HIGH VALUE — IMMEDIATE P0)

### Stripe Live Secret Key
- **Pattern**: `sk_live_[A-Za-z0-9]{24,}`
- **Validation**: `GET https://api.stripe.com/v1/balance` with Basic auth `sk_live_xxx:`
- **Success**: 200 with balance JSON.
- **Severity**: P0. Stripe key = move money.

### Stripe Live Restricted Key
- **Pattern**: `rk_live_[A-Za-z0-9]{24,}`
- **Validation**: same balance endpoint, may 403 depending on permissions.
- **Severity**: P1-P0 depending on scope.

### Stripe Test Key
- **Pattern**: `sk_test_`, `rk_test_`, `pk_test_`
- **Severity**: P3-P2 (test mode only — but reveals integration patterns and account exists).

### Stripe Publishable Key
- **Pattern**: `pk_live_[A-Za-z0-9]{24,}`
- **Severity**: P4 (designed to be public).

### Stripe Webhook Signing Secret
- **Pattern**: `whsec_[A-Za-z0-9]{32,}`
- **Validation**: cannot validate directly; presence in source = config leak.
- **Severity**: P2 (allows spoofing webhook events).

### Stripe Connect Client Secret
- **Pattern**: `sk_live_` for connected accounts.

### PayPal Live Client ID + Secret
- **Pattern**: client_id is alphanumeric ~80 chars; secret similar
- **Validation**: 
  ```
  POST https://api-m.paypal.com/v1/oauth2/token
  Auth: Basic base64(client_id:secret)
  Body: grant_type=client_credentials
  ```
  Returns access_token if valid.
- **Severity**: P0.

### PayPal Sandbox
- Uses `api-m.sandbox.paypal.com` — P3.

### PayPal Braintree Server Key
- **Pattern**: 32-char alphanumeric for `private_key`
- **Validation**: 
  ```python
  import braintree
  gateway = braintree.BraintreeGateway(
      braintree.Configuration(braintree.Environment.Production,
                              merchant_id=mid, public_key=pk, private_key=sk))
  gateway.transaction.search(...)  # or simpler: gateway.merchant_account.all()
  ```
- **Severity**: P0.

### Braintree API Key
- **Pattern**: requires merchant_id + public_key + private_key triplet.

### Square Access Token
- **Pattern**: `EAAAE[A-Za-z0-9_-]{60,}` (production), `sandbox-sq0atb-` (sandbox)
- **Validation**: `GET https://connect.squareup.com/v2/locations` with Bearer.
- **Severity**: P0.

### Square Application Secret
- **Pattern**: `sq0csp-[A-Za-z0-9_-]{43}`

### Square OAuth Token
- **Pattern**: `EAAAEO`

### Adyen API Key
- **Pattern**: `AQE[A-Za-z0-9]{200+}`
- **Validation**: small POST to checkout endpoint with valid structure but invalid 
  amount — observe auth pass.

### PayU API Key
- **Pattern**: depends on region (PayU India vs PayU LATAM differ)
- India: `merchantKey` + `salt` pair, alphanumeric.
- **Validation**: small request to PayU API with hash; observe auth pass vs reject.
- **Severity**: P0.

### Razorpay Key ID + Secret
- **Pattern**: `rzp_live_[A-Za-z0-9]{14}` (key_id) + 24-char secret
- **Test mode**: `rzp_test_`
- **Validation**: `GET https://api.razorpay.com/v1/payments` with Basic auth (key_id:secret).
- **Severity**: P0 for live.

### Paytm Merchant Key
- **Pattern**: `MID` + alphanumeric merchant key
- **Validation**: status query API.

### Instamojo API Key + Auth Token
- **Validation**: `GET https://www.instamojo.com/api/1.1/payments/` with X-Api-Key, X-Auth-Token.

### CCAvenue Working Key
- 32-char hex.

### Cashfree Client ID + Secret
- **Pattern**: `CF` + numeric client_id + alphanumeric secret
- **Validation**: token exchange endpoint.

### Klarna API Key
- **Pattern**: `klarna_test_api_` or `klarna_live_api_` prefix
- **Validation**: small GET against orders endpoint with Basic auth.

### Authorize.Net API Login ID + Transaction Key
- **Validation**: small `getMerchantDetailsRequest` SOAP/JSON call.

### Worldpay Service Key
- **Pattern**: starts with `T_S_` (test) or `L_S_` (live)
- **Validation**: orders API.

### 2Checkout (Verifone) Account Number + Secret
- **Validation**: API list call.

### Mollie API Key
- **Pattern**: `live_[A-Za-z0-9]{30}` or `test_[A-Za-z0-9]{30}`
- **Validation**: `GET https://api.mollie.com/v2/methods` with Bearer.
- **Severity**: P0 for live.

### Stripe Identity / Stripe Issuing Keys
- Subkeys of main Stripe — same validation.

### GoCardless Access Token
- **Pattern**: `live_[A-Za-z0-9_-]{40+}`, `sandbox_`
- **Validation**: `GET https://api.gocardless.com/customers` with Bearer + `GoCardless-Version` header.

### Plaid Client ID + Secret
- **Pattern**: client_id is 24 chars hex; secret is 30 chars hex
- **Validation**: `POST https://production.plaid.com/institutions/get` with `client_id`, `secret`, `count: 1`, `country_codes: ["US"]` in body. Sandbox URL similar.
- **Severity**: P0 (banking data).

### Wise (TransferWise) API Token
- **Pattern**: UUID
- **Validation**: `GET https://api.transferwise.com/v1/profiles` with Bearer.

### Coinbase API Key
- **Pattern**: 32-char alphanumeric key + 64-char secret
- **Validation**: signed request to `/v2/user`.

### Coinbase Commerce API Key
- **Pattern**: UUID
- **Validation**: `GET https://api.commerce.coinbase.com/charges` with `X-CC-Api-Key`.

### Binance API Key + Secret
- **Pattern**: 64-char alphanumeric each
- **Validation**: signed request to `/api/v3/account` with HMAC-SHA256.

### Kraken / KuCoin / OKX exchange keys
- Various; signed validation.

### MercadoPago Access Token
- **Pattern**: `APP_USR-[A-Za-z0-9-]{50+}` (live), `TEST-` prefix for test
- **Validation**: `GET https://api.mercadopago.com/users/me` with Bearer.

### Wave Apps API Key
- **Validation**: `POST https://gql.waveapps.com/graphql/public` with Bearer.

### QuickBooks OAuth Token
- **Validation**: company info endpoint.

### Xero API Token
- **Validation**: `GET https://api.xero.com/connections` with Bearer.

### FreshBooks OAuth Token
- **Validation**: account list endpoint.

---

## COMMUNICATION & MESSAGING

### Slack Bot Token
- **Pattern**: `xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}`
- **Validation**: `POST https://slack.com/api/auth.test` with `Authorization: Bearer <token>`
- **Success**: `{"ok": true, "team": "...", "user": "..."}`
- **Severity**: P1-P0 (workspace access).

### Slack User Token
- **Pattern**: `xoxp-`

### Slack App-Level Token
- **Pattern**: `xapp-1-`

### Slack Workflow Token
- **Pattern**: `xoxa-`

### Slack Refresh Token
- **Pattern**: `xoxr-`

### Slack Webhook URL
- **Pattern**: `https://hooks.slack.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}`
- **Validation**: send a benign test message (`{"text":"automated security test - please ignore"}`) — generates noise. Better: just identify as found, severity P2.
- **Severity**: P3-P2 (spam/phishing risk).

### Discord Bot Token
- **Pattern**: `[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}` (3 base64 segments, like JWT shape but Discord-flavored)
- **Validation**: `GET https://discord.com/api/v10/users/@me` with `Authorization: Bot <token>`.
- **Severity**: P1.

### Discord Webhook URL
- **Pattern**: `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}`
- **Validation**: GET the webhook URL — returns webhook metadata if valid.

### Telegram Bot Token
- **Pattern**: `[0-9]{8,10}:[A-Za-z0-9_-]{35}`
- **Validation**: `GET https://api.telegram.org/bot<TOKEN>/getMe`
- **Severity**: P2-P1.

### Microsoft Teams Webhook
- **Pattern**: `https://outlook.office.com/webhook/[A-Z0-9-]+/...` or `https://*.webhook.office.com/...`

### Twilio Account SID + Auth Token
- **Pattern**: SID starts with `AC` + 32 hex; auth token is 32 hex
- **Validation**: `GET https://api.twilio.com/2010-04-01/Accounts/<SID>.json` with Basic auth (SID:token).
- **Severity**: P0 (SMS/voice = real money + phishing).

### Twilio API Key SID
- **Pattern**: `SK[a-f0-9]{32}` (paired with secret).

### Twilio Verify Service SID
- **Pattern**: `VA[a-f0-9]{32}`.

### MessageBird Access Key
- **Pattern**: `live_[A-Za-z0-9]{25}` or `test_[A-Za-z0-9]{25}`
- **Validation**: `GET https://rest.messagebird.com/balance` with `Authorization: AccessKey <key>`.

### Vonage (Nexmo) API Key + Secret
- **Pattern**: 8-char key + 16-char secret
- **Validation**: `GET https://rest.nexmo.com/account/get-balance?api_key=<k>&api_secret=<s>`.

### Plivo Auth ID + Token
- **Validation**: `GET https://api.plivo.com/v1/Account/<auth_id>/` with Basic auth.

### Sinch / Bandwidth / TextMagic / ClickSend
- Each has a balance/account endpoint suitable for validation.

### SendGrid API Key
- **Pattern**: `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`
- **Validation**: `GET https://api.sendgrid.com/v3/scopes` with Bearer.
- **Severity**: P1-P0 (email send = phishing capability).

### Mailgun API Key
- **Pattern**: `key-[a-f0-9]{32}` (legacy), or just alphanumeric (newer)
- **Validation**: `GET https://api.mailgun.net/v3/domains` with Basic auth (`api:<key>`).

### Mailgun Webhook Signing Key
- **Pattern**: alphanumeric — used to sign webhooks.

### Mailchimp API Key
- **Pattern**: `[a-f0-9]{32}-us[0-9]{1,2}` (datacenter suffix)
- **Validation**: `GET https://<dc>.api.mailchimp.com/3.0/` with Basic auth (`anystring:<key>`).
- **Severity**: P1 (email lists, automation).

### Mandrill API Key (Mailchimp Transactional)
- **Pattern**: 22-char alphanumeric
- **Validation**: `POST https://mandrillapp.com/api/1.0/users/ping.json` body `{"key":"<KEY>"}`.

### Postmark Server Token
- **Pattern**: UUID
- **Validation**: `GET https://api.postmarkapp.com/server` with `X-Postmark-Server-Token`.

### Amazon SES (uses AWS keys)

### SparkPost API Key
- **Validation**: `GET https://api.sparkpost.com/api/v1/account` with Bearer.

### Resend API Key
- **Pattern**: `re_[A-Za-z0-9_]{20,}`
- **Validation**: `GET https://api.resend.com/domains` with Bearer.

### Loops.so API Key
- **Pattern**: alphanumeric
- **Validation**: `GET https://app.loops.so/api/v1/api-key` with Bearer.

### Klaviyo Private Key
- **Pattern**: `pk_[A-Za-z0-9]{34}`
- **Validation**: `GET https://a.klaviyo.com/api/accounts/` with `Authorization: Klaviyo-API-Key <key>`.

### HubSpot Private App Token
- **Pattern**: `pat-na1-[a-f0-9-]{36}` (NA region), `pat-eu1-` (EU)
- **Validation**: `GET https://api.hubapi.com/crm/v3/objects/contacts?limit=1` with Bearer.

### HubSpot Legacy API Key
- **Pattern**: UUID
- **Validation**: `GET https://api.hubapi.com/contacts/v1/lists/all/contacts/all?hapikey=<KEY>` (deprecated but may still work).

### Intercom Access Token
- **Pattern**: `dG9rOj` prefix base64 (about 60+ chars)
- **Validation**: `GET https://api.intercom.io/me` with Bearer.

### Drift Access Token
- **Validation**: contacts list endpoint.

### Zendesk OAuth Token
- **Validation**: `GET https://<subdomain>.zendesk.com/api/v2/users/me.json` with Bearer.

### Freshdesk API Key
- **Validation**: `GET https://<sub>.freshdesk.com/api/v2/agents/me` with Basic (`<key>:X`).

### Help Scout OAuth Token
- **Validation**: users endpoint.

---

## AI / LLM PROVIDERS

### OpenAI API Key (legacy)
- **Pattern**: `sk-[A-Za-z0-9]{48}`
- **Validation**: `GET https://api.openai.com/v1/models` with Bearer. Cost-free.
- **Severity**: P1-P0. Live OpenAI key on a popular platform = $$$ for victim quickly.

### OpenAI Project-Scoped Key
- **Pattern**: `sk-proj-[A-Za-z0-9_-]{60,}`
- **Validation**: same.

### OpenAI Service Account Key
- **Pattern**: `sk-svcacct-[A-Za-z0-9_-]{50+}`

### OpenAI User Key (newer)
- **Pattern**: `sk-user-`

### OpenAI Admin Key
- **Pattern**: `sk-admin-` — DANGEROUS, account-level.

### Anthropic API Key
- **Pattern**: `sk-ant-api03-[A-Za-z0-9_-]{93,}`
- **Validation**: `POST https://api.anthropic.com/v1/messages` with minimal payload 
  `{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}` 
  — costs ~$0.0001. Or just send malformed payload to see auth-pass-then-validation-fail.
- **Severity**: P1-P0.

### Cohere API Key
- **Pattern**: alphanumeric ~40 chars (no fixed prefix consistently)
- **Validation**: `POST https://api.cohere.ai/v1/check-api-key` with Bearer.

### HuggingFace Token
- **Pattern**: `hf_[A-Za-z0-9]{34,}`
- **Validation**: `GET https://huggingface.co/api/whoami-v2` with Bearer.
- **Severity**: P2-P1 (private model access, write access to user repos).

### Replicate API Token
- **Pattern**: `r8_[A-Za-z0-9]{37}`
- **Validation**: `GET https://api.replicate.com/v1/account` with `Token <key>`.

### Together AI API Key
- **Pattern**: 64-char hex
- **Validation**: `GET https://api.together.xyz/v1/models` with Bearer.

### Groq API Key
- **Pattern**: `gsk_[A-Za-z0-9]{50+}`
- **Validation**: `GET https://api.groq.com/openai/v1/models` with Bearer.

### Perplexity API Key
- **Pattern**: `pplx-[a-f0-9]{40+}`
- **Validation**: `POST https://api.perplexity.ai/chat/completions` with minimal payload.

### Mistral API Key
- **Pattern**: 32-char alphanumeric
- **Validation**: `GET https://api.mistral.ai/v1/models` with Bearer.

### OpenRouter API Key
- **Pattern**: `sk-or-v1-[a-f0-9]{64}`
- **Validation**: `GET https://openrouter.ai/api/v1/auth/key` with Bearer.

### DeepSeek API Key
- **Pattern**: `sk-[A-Za-z0-9]{32}` (collides with OpenAI shape)
- **Validation**: `GET https://api.deepseek.com/v1/models` with Bearer.

### Fireworks API Key
- **Pattern**: alphanumeric
- **Validation**: `GET https://api.fireworks.ai/inference/v1/models` with Bearer.

### Anyscale Endpoint Key
- Similar OpenAI-compat API.

### NVIDIA NIM / NGC API Key
- **Pattern**: `nvapi-[A-Za-z0-9_-]{60+}`
- **Validation**: `GET https://api.nvcf.nvidia.com/v2/nvcf/functions` with Bearer.

### AWS Bedrock (uses AWS keys + region check for Bedrock service availability)

### Azure OpenAI (uses Azure SP credentials + endpoint URL)
- **Pattern**: endpoint URL contains `.openai.azure.com` + key
- **Validation**: `GET https://<endpoint>/openai/models?api-version=...` with `api-key` header.

### Vercel AI SDK provider key (AI Gateway)
- Various provider-specific.

### LangChain LangSmith API Key
- **Pattern**: `lsv2_pt_[A-Za-z0-9]{40+}`
- **Validation**: `GET https://api.smith.langchain.com/api/v1/info` with `x-api-key`.

### Pinecone API Key
- **Pattern**: UUID format
- **Validation**: `GET https://api.pinecone.io/indexes` with `Api-Key: <key>`.

### Weaviate Cloud API Key
- **Validation**: `GET https://<cluster>.weaviate.network/v1/meta` with Bearer.

### Qdrant API Key (cloud)
- **Validation**: `GET https://<cluster>.qdrant.io/collections` with `api-key` header.

### Chroma Cloud API Key

### Modal Token ID + Secret
- **Pattern**: `ak-[A-Za-z0-9]{16}` (token id) + `as-` (secret)
- **Validation**: Modal API call.

### RunPod API Key
- **Pattern**: alphanumeric 30+ chars
- **Validation**: `POST https://api.runpod.io/graphql` with `Authorization: Bearer`.

### Brev / Lambda Cloud / Paperspace
- Each has auth/account endpoint.

---

## ANALYTICS, MONITORING, OBSERVABILITY

### Datadog API Key
- **Pattern**: 32-char hex
- **Validation**: `GET https://api.datadoghq.com/api/v1/validate` with `DD-API-KEY` header.
- **EU**: `https://api.datadoghq.eu/...`
- **Severity**: P1.

### Datadog APP Key
- **Pattern**: 40-char hex (paired with API key for advanced ops)
- **Validation**: `GET https://api.datadoghq.com/api/v1/dashboard` with both headers.

### New Relic License Key
- **Pattern**: `eu01xx[A-Za-z0-9]{34}` or `[a-f0-9]{40}NRAL`
- **Validation**: `POST https://insights-collector.newrelic.com/v1/accounts/<id>/events` with `Api-Key` — but needs account_id.

### New Relic User API Key
- **Pattern**: `NRAK-[A-Z0-9]{27}`
- **Validation**: GraphQL query against `api.newrelic.com/graphql`.

### New Relic Insights Insert Key
- **Pattern**: `NRII-`

### New Relic Browser License Key
- **Pattern**: `NRBR-` or `NRJS-`

### Sentry Auth Token
- **Pattern**: `sntrys_` (org-level) or 64-char hex (user/integration)
- **Validation**: `GET https://sentry.io/api/0/projects/` with Bearer.
- **Severity**: P1.

### Sentry DSN
- **Pattern**: `https://<key>@<org>.ingest.sentry.io/<project_id>`
- **Severity**: P3 (usually meant to be public-ish but can be abused for spam).

### Rollbar Access Token
- **Pattern**: 32-char hex
- **Validation**: `GET https://api.rollbar.com/api/1/projects/?access_token=<TOKEN>`.

### Bugsnag API Key
- **Pattern**: 32-char hex
- **Validation**: `GET https://api.bugsnag.com/user` with `Authorization: token <key>`.

### Honeybadger API Key
- **Validation**: account endpoint.

### LogDNA / Mezmo Service Key
- **Validation**: ingest endpoint.

### Logtail Source Token
- **Pattern**: alphanumeric.

### Splunk HEC Token
- **Pattern**: UUID
- **Validation**: `POST https://<host>:8088/services/collector/event` with `Authorization: Splunk <token>` and minimal event.

### PagerDuty API Key (v2)
- **Pattern**: `u+` prefix or 20-char alphanumeric
- **Validation**: `GET https://api.pagerduty.com/users` with `Authorization: Token token=<key>` and `Accept: application/vnd.pagerduty+json;version=2`.

### PagerDuty Integration Key (Routing Key)
- **Pattern**: 32-char alphanumeric
- **Validation**: send test event (creates a real incident — CAUTIOUS, prefer just identify).

### Opsgenie API Key
- **Pattern**: UUID
- **Validation**: `GET https://api.opsgenie.com/v2/account` with `Authorization: GenieKey <key>`.

### VictorOps / Splunk On-Call REST URL
- Includes API key in URL.

### StatusPage API Key
- **Pattern**: alphanumeric
- **Validation**: `GET https://api.statuspage.io/v1/pages` with `OAuth <key>` header.

### Better Stack (formerly Better Uptime) API Token
- **Validation**: monitors endpoint with Bearer.

### Pingdom API Token
- **Validation**: checks endpoint.

### UptimeRobot API Key
- **Pattern**: starts with `u` followed by digits and dashes
- **Validation**: `POST https://api.uptimerobot.com/v2/getMonitors` with `api_key=<KEY>` form body.

### Cronitor API Key
- **Validation**: monitors endpoint.

### LaunchDarkly Access Token
- **Pattern**: `api-[a-f0-9-]{36}` or starts with feature-flag-specific prefix
- **Validation**: `GET https://app.launchdarkly.com/api/v2/projects` with Authorization.

### Optimizely Personal Access Token
- **Validation**: projects endpoint.

### Mixpanel Service Account
- **Validation**: events endpoint with Basic auth.

### Amplitude API Key + Secret
- **Validation**: identify endpoint.

### Segment Write Key
- **Pattern**: 32-char alphanumeric
- **Validation**: track endpoint with Basic auth (writeKey:).

### PostHog Personal API Key
- **Pattern**: `phx_[A-Za-z0-9]{43}`
- **Validation**: `GET https://app.posthog.com/api/users/@me/` with Bearer.

### PostHog Project API Key
- **Pattern**: `phc_[A-Za-z0-9]{43}` — designed to be public, P4.

### Heap Analytics API Key
- **Validation**: account endpoint.

### Plausible Analytics API Key
- **Validation**: stats endpoint.

### FullStory API Key
- **Validation**: account endpoint.

---

## DEV & PRODUCTIVITY TOOLS

### Linear API Key
- **Pattern**: `lin_api_[A-Za-z0-9]{40}`
- **Validation**: GraphQL `viewer { id }` query against `api.linear.app/graphql` with Bearer.
- **Severity**: P1.

### Notion Integration Token
- **Pattern**: `secret_[A-Za-z0-9]{43}` or `ntn_[A-Za-z0-9]{40+}` (newer)
- **Validation**: `GET https://api.notion.com/v1/users/me` with Bearer + `Notion-Version: 2022-06-28`.
- **Severity**: P1.

### Asana Personal Access Token
- **Pattern**: `1/[0-9]+:[a-f0-9]{32}` (numeric id + hex)
- **Validation**: `GET https://app.asana.com/api/1.0/users/me` with Bearer.

### Trello API Key + Token
- **Pattern**: 32-char alphanumeric key, 64-char token
- **Validation**: `GET https://api.trello.com/1/members/me?key=<KEY>&token=<TOKEN>`.

### Monday.com API Token
- **Pattern**: JWT-shaped (3 base64 segments)
- **Validation**: GraphQL `me { id }` against `api.monday.com/v2`.

### ClickUp Personal Token
- **Pattern**: `pk_[0-9]+_[A-Z0-9]{32}`
- **Validation**: `GET https://api.clickup.com/api/v2/user` with token in `Authorization`.

### Airtable Personal Access Token
- **Pattern**: `pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`
- **Validation**: `GET https://api.airtable.com/v0/meta/whoami` with Bearer.
- **Severity**: P1 (full base access).

### Airtable Legacy API Key
- **Pattern**: `key[A-Za-z0-9]{14}` — deprecated, P2.

### Coda API Token
- **Pattern**: alphanumeric
- **Validation**: `GET https://coda.io/apis/v1/whoami` with Bearer.

### Figma Personal Access Token
- **Pattern**: `figd_[A-Za-z0-9_-]{40+}` (newer), 64-char hex (legacy)
- **Validation**: `GET https://api.figma.com/v1/me` with `X-Figma-Token`.

### Canva Connect API Key

### Adobe IO / Creative SDK Tokens
- Various.

### InVision API Token
- **Validation**: account endpoint.

### Miro REST API Token
- **Validation**: `GET https://api.miro.com/v2/teams` with Bearer.

### Lucidchart / Lucidspark Token
- **Validation**: documents endpoint.

### Loom OAuth Token
- **Validation**: workspace endpoint.

### Calendly OAuth Token
- **Validation**: `GET https://api.calendly.com/users/me` with Bearer.

### Cal.com API Key
- **Pattern**: `cal_live_[A-Za-z0-9]{32+}`
- **Validation**: `GET https://api.cal.com/v1/me?apiKey=<KEY>`.

### Salesforce Session ID / OAuth Token
- **Pattern**: complex, includes `00D` (org id) or starts with `00D`
- **Validation**: `GET https://<instance>.salesforce.com/services/data/v55.0/` with Bearer.

### Salesforce Connected App Consumer Secret
- Used in OAuth flow.

### ServiceNow OAuth Token
- **Validation**: `GET https://<instance>.service-now.com/api/now/table/sys_user?sysparm_limit=1` with Bearer.

### Workday Tokens
- Various; SOAP/REST endpoints.

### SAP Concur OAuth
- **Validation**: identity endpoint.

### Microsoft Graph Token
- **Validation**: `GET https://graph.microsoft.com/v1.0/me` with Bearer.

### Google OAuth Access Token
- **Pattern**: `ya29.[A-Za-z0-9_-]{60+}`
- **Validation**: `GET https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=<TOKEN>` (free).

### Google Refresh Token
- **Pattern**: `1//[A-Za-z0-9_-]{40+}`
- **Validation**: refresh against token endpoint.

### Dropbox Access Token
- **Pattern**: `sl.[A-Za-z0-9_-]{120+}` (short-lived) or longer for app keys
- **Validation**: `POST https://api.dropboxapi.com/2/users/get_current_account` with Bearer.

### Box API Token
- **Validation**: `GET https://api.box.com/2.0/users/me` with Bearer.

### OneDrive / SharePoint via MS Graph (above).

---

## CDN, DNS, EDGE

### Cloudflare (above)

### AWS CloudFront (uses AWS keys)

### Akamai EdgeGrid Tokens
- **Pattern**: 4-tuple (host, client_token, client_secret, access_token)
- **Validation**: signed request to `/papi/v1/contracts`.

### Fastly (above)

### KeyCDN API Key
- **Validation**: account endpoint.

### BunnyCDN API Key
- **Pattern**: alphanumeric
- **Validation**: `GET https://api.bunny.net/pullzone` with `AccessKey` header.

### CDN77 API Token
- **Validation**: services endpoint.

### Imperva / Incapsula API ID + Key
- **Validation**: account/list endpoint.

### Sucuri API Key + Secret
- **Validation**: signed account endpoint.

### Namecheap API Key
- **Validation**: `GET https://api.namecheap.com/xml.response?ApiUser=...&ApiKey=...&UserName=...&Command=namecheap.users.getBalances`.

### GoDaddy API Key + Secret
- **Validation**: `GET https://api.godaddy.com/v1/domains` with `Authorization: sso-key <key>:<secret>`.

### Route53 (uses AWS)

### Cloudflare Workers Token
- subset of CF token.

---

## CI / CD / DEPLOYMENT

### CircleCI Personal Token
- **Pattern**: 40-char hex
- **Validation**: `GET https://circleci.com/api/v2/me` with `Circle-Token` header.

### Travis CI Token
- **Pattern**: 22-char alphanumeric
- **Validation**: `GET https://api.travis-ci.com/user` with `Authorization: token <key>`.

### Jenkins API Token
- **Pattern**: 32-34 char hex
- **Validation**: `GET <jenkins-url>/api/json` with Basic auth (user:token).

### TeamCity Token
- **Validation**: server info endpoint.

### Buildkite API Token
- **Pattern**: 40-char hex
- **Validation**: `GET https://api.buildkite.com/v2/user` with Bearer.

### Drone CI Token
- JWT-like.

### Argo CD API Token (above in admin panels)

### Octopus Deploy API Key
- **Pattern**: `API-[A-Z0-9]{26}`
- **Validation**: `GET <server>/api/users/me` with `X-Octopus-ApiKey`.

### Bamboo PAT
- **Validation**: user info endpoint.

### Spinnaker (no API key typically — uses cert-based auth).

---

## DATABASES (HOSTED)

### MongoDB Atlas Public + Private Key
- **Pattern**: 8-char public + 36-char UUID private
- **Validation**: digest auth `GET https://cloud.mongodb.com/api/atlas/v1.0/orgs`.

### Supabase Service Role Key
- **Pattern**: JWT-shape, role claim is `service_role` — DANGEROUS, full DB bypass
- **Validation**: decode JWT, then `GET https://<project>.supabase.co/rest/v1/` with `apikey` and `Authorization` headers.
- **Severity**: P0.

### Supabase Anon Key
- **Pattern**: JWT, role `anon` — designed to be public, P4.

### PlanetScale Service Token
- **Pattern**: `pscale_tkn_[A-Za-z0-9]{40+}`
- **Validation**: `GET https://api.planetscale.com/v1/organizations` with `Authorization: <token>`.

### Neon API Key
- **Pattern**: `neon_[A-Za-z0-9_-]{32+}`
- **Validation**: `GET https://console.neon.tech/api/v2/projects` with Bearer.

### Turso Database Token
- **Pattern**: JWT.

### CockroachDB Cloud API Key
- **Validation**: clusters endpoint.

### Snowflake Personal Access Token
- **Validation**: query info endpoint.

### Databricks PAT
- **Pattern**: `dapi[a-f0-9]{32}`
- **Validation**: `GET https://<workspace>.cloud.databricks.com/api/2.0/clusters/list` with Bearer.

### BigQuery (via GCP service account)

### Firebase Database Secret (legacy)
- **Pattern**: 40-char alphanumeric
- **Validation**: GET against database with `?auth=<secret>`.

### Firebase Cloud Messaging Server Key (legacy)
- **Pattern**: starts with `AAAA` for legacy, base64
- **Validation**: send test FCM message (avoid — generates traffic).

### Realm / MongoDB Realm Token
- **Validation**: app endpoint.

### CouchDB / Couchbase admin tokens (above in admin panels)

### Redis Cloud / Upstash Tokens
- **Upstash REST API token**: `AX_AAAAA...`
- **Validation**: `GET https://<region>.upstash.io/info` with Bearer.

### Aiven API Token
- **Validation**: account endpoint.

### ElephantSQL API Key
- **Validation**: instances endpoint.

---

## SECURITY / IDENTITY

### Auth0 API Token (Management API)
- **Pattern**: JWT, audience `https://<tenant>.auth0.com/api/v2/`
- **Validation**: `GET https://<tenant>.auth0.com/api/v2/clients` with Bearer.
- **Severity**: P1-P0.

### Auth0 Client Secret
- Pair with client_id; use in token exchange.

### Okta API Token
- **Pattern**: `00[A-Za-z0-9_-]{40}`
- **Validation**: `GET https://<org>.okta.com/api/v1/users/me` with `Authorization: SSWS <token>`.
- **Severity**: P0.

### Okta OAuth Tokens
- standard JWT.

### Clerk Secret Key
- **Pattern**: `sk_live_[A-Za-z0-9]{40+}` or `sk_test_`
- **Validation**: `GET https://api.clerk.com/v1/users` with Bearer.

### Clerk Publishable Key
- **Pattern**: `pk_live_` — designed to be public.

### WorkOS API Key
- **Pattern**: `sk_live_[A-Za-z0-9]{40+}` or `sk_test_`
- **Validation**: `GET https://api.workos.com/directories` with Bearer.

### Stytch Secret
- **Pattern**: `secret-test-` or `secret-live-` prefix
- **Validation**: project endpoint.

### Frontegg Client ID + Secret
- **Validation**: token exchange.

### FusionAuth API Key
- **Validation**: `GET <host>/api/user` with `Authorization` header.

### Firebase Auth Service Account (uses GCP service account)

### Cognito (uses AWS)

### Keycloak Admin Token
- short-lived Bearer.

### LastPass / 1Password / Bitwarden API tokens
- treat as P0; account access.

### Vault Tokens (HashiCorp)
- **Pattern**: `hvs.[A-Za-z0-9_-]{90+}` (newer), or 26-char (legacy)
- **Validation**: `GET <vault>/v1/auth/token/lookup-self` with `X-Vault-Token`.
- **Severity**: P0.

### AWS Secrets Manager / Parameter Store (uses AWS)

### Doppler Service Token
- **Pattern**: `dp.st.[A-Za-z0-9_.]{40+}`
- **Validation**: `GET https://api.doppler.com/v3/configs` with Basic (`token:`).

### Doppler Personal Token
- **Pattern**: `dp.pt.`

### Infisical Service Token
- **Pattern**: `st.[A-Za-z0-9_.]+`
- **Validation**: secrets endpoint.

### EnvKey Token
- **Validation**: env endpoint.

---

## E-COMMERCE & MARKETPLACES

### Shopify Admin API Access Token
- **Pattern**: `shpat_[a-f0-9]{32}`
- **Validation**: `GET https://<shop>.myshopify.com/admin/api/2024-01/shop.json` with `X-Shopify-Access-Token`.
- **Severity**: P0.

### Shopify Storefront API Token
- **Pattern**: `shpss_[a-f0-9]{32}` (storefront secret) or 32-char hex public storefront token
- **Validation**: GraphQL against storefront endpoint.

### Shopify Custom App Token
- **Pattern**: `shpca_[a-f0-9]{32}`

### Shopify Partner Token
- **Pattern**: `shppa_[a-f0-9]{32}`

### Shopify App API Key + Secret
- public/secret pair.

### WooCommerce Consumer Key + Secret
- **Pattern**: `ck_[a-f0-9]{40}` + `cs_[a-f0-9]{40}`
- **Validation**: `GET https://<site>/wp-json/wc/v3/products?consumer_key=<CK>&consumer_secret=<CS>`.

### Magento API Key / Bearer Token
- **Validation**: REST endpoint with Bearer.

### BigCommerce Access Token
- **Validation**: `GET https://api.bigcommerce.com/stores/<hash>/v3/catalog/summary` with `X-Auth-Token`.

### Etsy API Key
- **Validation**: shops endpoint.

### eBay OAuth Token
- **Validation**: identity endpoint.

### Amazon SP-API Refresh Token
- **Validation**: token exchange + sellers endpoint.

### Walmart Marketplace Token
- **Validation**: items endpoint.

### Mercado Libre Access Token
- **Validation**: user endpoint.

---

## SHIPPING & LOGISTICS

### EasyPost API Key
- **Pattern**: `EZAK[a-f0-9]{32}` (production) or `EZTK[a-f0-9]{32}` (test)
- **Validation**: `GET https://api.easypost.com/v2/addresses` with Basic (key:).

### Shippo API Token
- **Pattern**: `shippo_live_[A-Za-z0-9]{40+}` or `shippo_test_`
- **Validation**: addresses endpoint.

### ShipStation API Key + Secret
- **Validation**: orders endpoint.

### Shipbob API Token
- **Validation**: orders endpoint.

### FedEx / UPS / DHL API tokens
- Each has rate-quote endpoint suitable for validation.

---

## MAPS, LOCATION, OTHER

### Google Maps API Key (above in GCP)

### Mapbox Public Token
- **Pattern**: `pk\.[A-Za-z0-9_-]{60+}\.[A-Za-z0-9_-]{20+}` — designed to be public, P4.

### Mapbox Secret Token
- **Pattern**: `sk\.[A-Za-z0-9_-]{60+}\.[A-Za-z0-9_-]{20+}`
- **Validation**: `GET https://api.mapbox.com/tokens/v2/<username>?access_token=<sk_token>`.
- **Severity**: P1.

### HERE Maps API Key
- **Validation**: geocoding endpoint.

### TomTom API Key
- **Validation**: search endpoint.

### Geoapify, OpenCage, LocationIQ — each has free-tier endpoint for validation.

---

## SOCIAL MEDIA

### Facebook App Access Token
- **Pattern**: `EAA[A-Za-z0-9]+`
- **Validation**: `GET https://graph.facebook.com/me?access_token=<TOKEN>`.

### Facebook App ID + Secret
- **Validation**: app token exchange.

### Instagram Basic Display Token (subset of FB graph).

### Twitter/X Bearer Token (App-only)
- **Pattern**: `AAAAAAAAAAAAAAAAAAAAA` long base64
- **Validation**: `GET https://api.x.com/2/users/me` with Bearer (or v1.1 if available).

### Twitter/X API Key + Secret + Access Token + Access Secret (OAuth 1.0a)
- **Validation**: OAuth-signed request to verify_credentials.

### Twitter/X OAuth 2.0 User Token
- **Pattern**: `7e..`-ish long.

### LinkedIn OAuth Access Token
- **Validation**: `GET https://api.linkedin.com/v2/me` with Bearer.

### Reddit OAuth Token
- **Validation**: `GET https://oauth.reddit.com/api/v1/me` with Bearer.

### TikTok for Business Token
- **Validation**: advertiser endpoint.

### YouTube API Key (uses GCP key)

### Vimeo Access Token
- **Pattern**: 32-char alphanumeric
- **Validation**: `GET https://api.vimeo.com/me` with Bearer.

### Twitch OAuth Token
- **Pattern**: 30-char alphanumeric
- **Validation**: `GET https://api.twitch.tv/helix/users` with `Authorization: Bearer <t>` + `Client-Id`.

### Pinterest Access Token
- **Validation**: `GET https://api.pinterest.com/v5/user_account` with Bearer.

### Snapchat Marketing API Token
- **Validation**: organizations endpoint.

---

## DOMAIN NAME / WHOIS

### Namecheap (above)
### GoDaddy (above)
### Cloudflare (above for DNS)
### NameSilo, Porkbun, Dynadot — each has API.

---

## CRYPTO / BLOCKCHAIN INFRA

### Infura API Key
- **Pattern**: 32-char hex (project ID)
- **Validation**: `POST https://mainnet.infura.io/v3/<KEY>` with JSON-RPC `eth_blockNumber`.

### Alchemy API Key
- **Pattern**: 32-char alphanumeric
- **Validation**: `POST https://eth-mainnet.g.alchemy.com/v2/<KEY>` with JSON-RPC.

### QuickNode endpoint URL with key
- **Validation**: JSON-RPC.

### Moralis API Key
- **Validation**: blocks endpoint.

### Etherscan API Key
- **Pattern**: 34-char alphanumeric
- **Validation**: `GET https://api.etherscan.io/api?module=stats&action=ethsupply&apikey=<KEY>`.

### Helius / Bitquery / Covalent / Nansen — each has account endpoint.

---

## MISCELLANEOUS

### Algolia App ID + Admin API Key
- **Pattern**: app id is 10 chars uppercase; admin key is 32-char alphanumeric
- **Validation**: `GET https://<APP_ID>-dsn.algolia.net/1/indexes` with `X-Algolia-Application-Id` + `X-Algolia-API-Key`.
- **Severity**: P1 (data manipulation).

### Algolia Search-Only Key
- designed to be public.

### Elasticsearch / OpenSearch API key
- **Validation**: `_cluster/health` with `Authorization: ApiKey <base64>`.

### Stream Chat / Stream Feeds API Key + Secret
- **Validation**: token-generation endpoint.

### Sendbird API Token
- **Validation**: applications endpoint.

### Pusher App ID + Key + Secret
- **Validation**: signed request to channels endpoint.

### Ably API Key
- **Pattern**: `<keyName>:<keySecret>` colon-separated
- **Validation**: stats endpoint.

### Agora App ID + Certificate
- **Validation**: token-build endpoint.

### Daily.co API Key
- **Pattern**: 64-char alphanumeric
- **Validation**: `GET https://api.daily.co/v1/rooms` with Bearer.

### LiveKit API Key + Secret
- **Validation**: signed JWT generation, then list rooms.

### Zoom JWT (legacy) / Zoom OAuth
- **Validation**: `GET https://api.zoom.us/v2/users/me` with Bearer.

### Webex Access Token
- **Validation**: people/me endpoint.

### RingCentral Token
- **Validation**: account endpoint.

### Dialpad Token
- **Validation**: users endpoint.

### Aircall Token
- **Validation**: users endpoint.

### Front App Token
- **Validation**: inboxes endpoint.

### Crisp / Tidio / LiveChat — each has account endpoint.

---

## VALIDATION-WORKFLOW NOTES FOR THE SYSTEM

1. **Per-secret-type validator module** lives in `validate/<provider>.py`. Each
   module exports `pattern: re.Pattern`, `name: str`, `severity_default: int`, 
   and `async def validate(secret_value: str) -> ValidationResult`.

2. **Pattern matching first, validation second.** Pattern match is cheap (regex 
   over text). Validation makes a network call. Don't validate the same value twice.

3. **Validators must be safe.** No state changes. No spam. No quota burning beyond 
   the minimum required call. Document the request in evidence.

4. **Validation result contains**: `is_valid: bool`, `confidence: 'high'|'medium'|'low'`, 
   `account_info: dict` (optional, e.g. AWS account ID, Stripe account ID, GitHub 
   user — proves the key is real), `validated_at: timestamp`, `request_evidence: 
   ProbeResult`.

5. **Some secrets cannot be safely validated in isolation** (e.g., Stripe webhook 
   signing secrets, generic JWT signing keys, encryption keys). Mark those as 
   "found, not validated" and rely on context (where it was found) for severity.

6. **Generic high-entropy strings** (Shannon entropy > 4.5, length > 20, no English 
   words) are detected as candidate secrets but lowest priority — high false 
   positive rate.

7. **Format-collision handling.** `sk-` prefix is used by OpenAI, DeepSeek, and others. 
   Try validators in order; first one that returns valid wins. Cache the negative 
   result for the failed validators against that exact value.

8. **Geographic/region detection.** AWS region inference from key (older keys can 
   sometimes hint), Mailchimp datacenter, Auth0 tenant — use response data to 
   pivot to other endpoints owned by the same account.

9. **Account enumeration after validation** (CAUTIOUS):
   - For AWS: also call `iam:GetAccountSummary`, `s3:ListBuckets` to estimate blast radius.
   - For GitHub: list repos, check scopes.
   - For Stripe: balance + last 5 charges (read-only) to confirm production volume.
   - Document every call in evidence; never go beyond read-only enumeration.

10. **Notification rules.** Live token validation always triggers an immediate 
    Discord ping with the token type, the account info (so I know who to notify), 
    and a "REVOKE THIS NOW" instruction in the message.

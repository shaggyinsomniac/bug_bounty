# Comprehensive Misconfiguration & Exposure Corpus for Bug Bounty Automation

This is the detection corpus for an automated bug bounty system focused on
misconfigurations, exposed files, exposed services, and known-default-credential
issues. Organized by category. Each entry includes detection paths/fingerprints,
validation strategy, evidence requirements, and notes on report-worthiness.

**Format per entry:**
- **Detection**: how to find it (path, header, response signature, port, Nuclei template ID where applicable)
- **Validation**: how to confirm it's real and not a 404 fallback / honeypot / WAF response
- **Evidence**: what to capture for the report
- **Severity hint**: typical bounty range and triage outcome
- **Chain potential**: what this enables if found

---

## CATEGORY 1: EXPOSED SOURCE CONTROL & VERSION CONTROL

### 1.1 Exposed `.git` directory
- **Detection**: GET `/.git/HEAD`, `/.git/config`, `/.git/logs/HEAD`, `/.git/index`
- **Validation**: Response must contain `ref: refs/heads/` (HEAD) or `[core]` block (config). 200 status with HTML body = false positive (SPA fallback).
- **Evidence**: Capture HEAD, config, and attempt full repo dump via `git-dumper`. Show the recovered source tree.
- **Severity**: P3-P1 depending on what's in the repo. Source code with hardcoded creds = P1.
- **Chain**: Recovered `.env`, hardcoded API keys, internal hostnames, JWT secrets, DB credentials.

### 1.2 Exposed `.svn` directory
- **Detection**: GET `/.svn/entries`, `/.svn/wc.db`, `/.svn/format`
- **Validation**: `wc.db` is SQLite, `format` is plaintext integer.
- **Evidence**: Dump via `svn-extractor` tools.
- **Severity**: P3-P2.

### 1.3 Exposed `.hg` (Mercurial)
- **Detection**: GET `/.hg/store/00manifest.i`, `/.hg/requires`
- **Validation**: Binary signatures.
- **Severity**: P3.

### 1.4 Exposed `.bzr` (Bazaar)
- **Detection**: GET `/.bzr/branch/branch.conf`, `/.bzr/checkout/dirstate`
- **Severity**: P4.

### 1.5 Exposed `CVS/` directory
- **Detection**: GET `/CVS/Entries`, `/CVS/Root`
- **Severity**: P4 (legacy, rare but still appears).

### 1.6 Git-related leaked files
- **Detection**: `/.gitignore`, `/.gitattributes`, `/.gitlab-ci.yml`, `/.github/workflows/*.yml`, `/.git-credentials`, `/.netrc`
- **Validation**: `.git-credentials` containing `https://user:pass@` = P1 immediate.
- **Severity**: `.gitignore` alone = informational; `.git-credentials` = P1.

---

## CATEGORY 2: EXPOSED ENVIRONMENT & CONFIG FILES

### 2.1 `.env` files (Laravel, Rails, Node, generic)
- **Detection paths**:
  - `/.env`, `/.env.backup`, `/.env.bak`, `/.env.local`, `/.env.dev`, `/.env.development`,
    `/.env.prod`, `/.env.production`, `/.env.staging`, `/.env.test`, `/.env.example` (low value),
    `/.env.save`, `/.env.old`, `/.env.swp`, `/.env.swo`, `/env`, `/env.js`, `/env.json`
  - In subdirectories: `/api/.env`, `/admin/.env`, `/app/.env`, `/config/.env`, `/storage/.env`
- **Validation**: Must contain `KEY=VALUE` line format. Look for `APP_KEY=`, `DB_PASSWORD=`, `AWS_`, `STRIPE_`, `MAIL_`. HTML response = false positive.
- **Evidence**: Full file contents (redact in report), parsed credential inventory, validation results per credential type.
- **Severity**: P2-P0 depending on contents. Live AWS root keys = P0.
- **Chain**: AWS/GCP/Azure cloud takeover, database access, third-party API abuse, mail server abuse.

### 2.2 PHP config files
- **Detection**: `/config.php`, `/config.php.bak`, `/config.php.swp`, `/config.php~`, `/config.inc.php`, `/configuration.php`, `/wp-config.php.bak`, `/wp-config.php.old`, `/wp-config.php.save`, `/wp-config.php~`, `/wp-config.txt`, `/wp-config.php.swp`
- **Validation**: PHP source visible (not executed) = leaked. `<?php` in response body confirms.
- **Severity**: P1-P0. WordPress `wp-config.php` with DB creds + auth keys = P0.

### 2.3 Java/Spring config
- **Detection**: `/application.yml`, `/application.properties`, `/application-dev.yml`, `/application-prod.yml`, `/bootstrap.yml`, `/application.json`, `/WEB-INF/web.xml`, `/WEB-INF/classes/application.properties`
- **Validation**: YAML/properties syntax with config keys.
- **Severity**: P2-P1.

### 2.4 Node.js config
- **Detection**: `/config.json`, `/config/default.json`, `/config/production.json`, `/ecosystem.config.js`, `/pm2.json`, `/.npmrc`, `/.yarnrc`
- **Validation**: `.npmrc` with `_authToken=` or `//registry.npmjs.org/:_authToken=` = P2 (NPM publish token leak).
- **Severity**: P3-P1.

### 2.5 Python config
- **Detection**: `/settings.py`, `/local_settings.py`, `/config.py`, `/secret_settings.py`, `/instance/config.py` (Flask), `/config/settings/production.py`
- **Severity**: P2-P1.

### 2.6 Ruby/Rails config
- **Detection**: `/config/database.yml`, `/config/secrets.yml`, `/config/master.key`, `/config/credentials.yml.enc`, `/config/application.yml`
- **Validation**: `master.key` is 32-char hex = P1.
- **Severity**: P2-P0.

### 2.7 Generic config exposures
- **Detection**: `/config/`, `/config.yml`, `/config.yaml`, `/config.toml`, `/config.ini`, `/settings.ini`, `/conf/`, `/etc/`, `/secrets/`, `/secrets.json`, `/secrets.yml`, `/credentials.json`, `/credentials.yml`, `/private.key`, `/server.key`, `/id_rsa`, `/id_dsa`, `/id_ecdsa`, `/id_ed25519`
- **Validation**: PEM block headers (`-----BEGIN RSA PRIVATE KEY-----`) = P1 immediate.
- **Severity**: Private keys exposed = P0.

### 2.8 Docker / orchestration config
- **Detection**: `/Dockerfile`, `/docker-compose.yml`, `/docker-compose.yaml`, `/docker-compose.override.yml`, `/.dockerignore`, `/Dockerfile.bak`, `/docker-compose.prod.yml`
- **Validation**: Docker syntax visible.
- **Severity**: P3-P1 depending on secrets baked in.

### 2.9 Kubernetes config
- **Detection**: `/kubeconfig`, `/.kube/config`, `/values.yaml`, `/secrets.yaml`, `/deployment.yaml`, `/ingress.yaml`
- **Validation**: `apiVersion:` and `kind:` keys present.
- **Severity**: kubeconfig with cluster admin = P0.

### 2.10 Terraform / IaC state
- **Detection**: `/terraform.tfstate`, `/terraform.tfstate.backup`, `/.terraform/terraform.tfstate`, `/main.tf`, `/variables.tf`, `/terraform.tfvars`
- **Validation**: JSON with `terraform_version` key (state files); HCL syntax (.tf files).
- **Severity**: tfstate files contain ALL infrastructure secrets in plaintext = P0.

### 2.11 Ansible config
- **Detection**: `/ansible.cfg`, `/inventory`, `/hosts`, `/group_vars/`, `/host_vars/`, `/playbook.yml`, `/site.yml`
- **Severity**: P3-P1.

### 2.12 CI/CD config files
- **Detection**: `/.travis.yml`, `/.circleci/config.yml`, `/.gitlab-ci.yml`, `/.github/workflows/*.yml`, `/Jenkinsfile`, `/azure-pipelines.yml`, `/bitbucket-pipelines.yml`, `/buildspec.yml`, `/cloudbuild.yaml`
- **Validation**: Look for hardcoded secrets in `env:` blocks.
- **Severity**: P3-P1.

---

## CATEGORY 3: EXPOSED BACKUP & ARCHIVE FILES

### 3.1 Database backups
- **Detection**: `/backup.sql`, `/dump.sql`, `/database.sql`, `/db.sql`, `/db_backup.sql`, `/mysql.sql`, `/mysqldump.sql`, `/postgres.sql`, `/backup.db`, `/database.sqlite`, `/db.sqlite3`, `/data.db`
- **Combinations**: prepend `/backup/`, `/backups/`, `/old/`, `/archive/`, `/dumps/`, `/db/`
- **Validation**: SQL syntax (`CREATE TABLE`, `INSERT INTO`) or SQLite magic bytes.
- **Severity**: P1-P0. Live user data = P0.

### 3.2 Filesystem backups
- **Detection patterns**: `/backup.zip`, `/backup.tar.gz`, `/backup.tar`, `/backup.tar.bz2`, `/backup.7z`, `/backup.rar`, `/site.zip`, `/site.tar.gz`, `/www.zip`, `/html.zip`, `/public_html.zip`, `/wwwroot.zip`
- **Auto-generated patterns**: `/<domain>.zip`, `/<domain>.tar.gz`, `/<sitename>.bak`, `/<year>.zip`, `/<year>-<month>.tar.gz`
- **Date-based**: `/backup-2024.zip`, `/backup-2025-01.tar.gz`, `/backup-202504.zip`
- **Validation**: Magic bytes (PK for ZIP, etc.). Content-Length > 1KB.
- **Severity**: P1-P0.

### 3.3 Editor swap & temp files
- **Detection**:
  - Vim: `/.index.php.swp`, `/.config.php.swp`, `/.env.swp`, `/.htaccess.swp` (any sensitive file with `.swp`)
  - Emacs: `/index.php~`, `/config.php~`
  - Backup suffixes: `.bak`, `.old`, `.orig`, `.save`, `.tmp`, `.copy`, `.txt`
- **Generation**: For each known config file, also try with each suffix.
- **Severity**: P3-P1.

### 3.4 IDE & editor metadata
- **Detection**: `/.vscode/settings.json`, `/.vscode/launch.json`, `/.idea/workspace.xml`, `/.idea/dataSources.xml` (database connection strings!), `/.idea/dataSources.local.xml`, `/.project`, `/.classpath`, `/.settings/`
- **Validation**: `dataSources.xml` containing `<jdbc-url>` with creds = P1.
- **Severity**: P3-P1.

### 3.5 OS metadata files
- **Detection**: `/.DS_Store`, `/Thumbs.db`, `/desktop.ini`
- **Validation**: `.DS_Store` magic bytes (`\x00\x00\x00\x01Bud1`). Parse to enumerate hidden files.
- **Severity**: P4 alone, P3 when used to enumerate other targets.

### 3.6 Log files
- **Detection**: `/log/`, `/logs/`, `/error.log`, `/access.log`, `/debug.log`, `/laravel.log`, `/storage/logs/laravel.log`, `/storage/logs/laravel-<date>.log`, `/var/log/`, `/app.log`, `/server.log`, `/php_errors.log`, `/error_log`
- **Validation**: Log line format with timestamps; look for stack traces with file paths, queries with parameters.
- **Severity**: P3-P1. Logs with session tokens / passwords / queries = P1.

### 3.7 Compiled/build artifacts
- **Detection**: `/dist/`, `/build/`, `/target/`, `/out/`, `/bin/`, `/obj/`, `/.next/`, `/.nuxt/`, `/coverage/` (test reports often expose source paths)
- **Severity**: P4-P3.

### 3.8 Webpack/sourcemap exposure
- **Detection**: `/main.js.map`, `/app.js.map`, `/bundle.js.map`, `/static/js/*.map`, `/assets/*.map`
- **Validation**: JSON with `sources`, `sourcesContent` arrays.
- **Severity**: P3 (source disclosure). Map files often contain full original source including comments and hardcoded secrets.
- **Chain**: Recovered source reveals API endpoints, hidden routes, secrets.

---

## CATEGORY 4: PHP-SPECIFIC EXPOSURES

### 4.1 PHPInfo pages
- **Detection**: `/phpinfo.php`, `/info.php`, `/i.php`, `/test.php`, `/php.php`, `/_phpinfo.php`, `/php_info.php`, `/pinfo.php`
- **Validation**: Response contains `phpinfo()` HTML structure (`<title>phpinfo()</title>`, table with `PHP Version`).
- **Evidence**: Capture PHP version, loaded modules, environment variables (often contains secrets), document_root, server signature.
- **Severity**: P3-P2. Environment vars with secrets = P2.

### 4.2 PHP error pages with full path disclosure
- **Detection**: Any URL that triggers a PHP error showing absolute file paths.
- **Validation**: `Warning:` / `Fatal error:` with `/var/www/`, `/home/<user>/`, `C:\xampp\` etc.
- **Severity**: P4 alone, P3 chained.

### 4.3 Composer / dependency files
- **Detection**: `/composer.json`, `/composer.lock`, `/vendor/`, `/vendor/composer/installed.json`
- **Severity**: P4 alone (informational), but enables targeted CVE lookup against deps.

### 4.4 Laravel-specific
- **4.4.1 Laravel debug mode**: Trigger 500 error, response shows Whoops/Ignition stack trace with full file paths, environment variables, request data.
  - Detection: any 500 error response containing `Whoops, looks like something went wrong` or `Ignition` branding.
  - Severity: P2-P1. With APP_KEY in env display = P1, chains to RCE via known Ignition CVEs (CVE-2021-3129).

- **4.4.2 Laravel Telescope** (debug toolkit, never for prod): `/telescope`, `/telescope/dashboard`, `/telescope/requests`
  - Validation: Telescope branding in HTML response.
  - Severity: P1. Exposes all requests with bodies, including auth tokens.

- **4.4.3 Laravel Debugbar**: Look for `/_debugbar/open` or `phpdebugbar` JS in responses.
  - Severity: P2.

- **4.4.4 Laravel Horizon**: `/horizon`, `/horizon/dashboard`
  - Severity: P2-P1. Exposes job queue contents.

- **4.4.5 Laravel storage symlink misconfig**: `/storage/logs/laravel.log` accessible.

### 4.5 WordPress-specific
- **4.5.1 wp-config.php exposures**: see 2.2.
- **4.5.2 `/wp-content/debug.log`**: WP debug log enabled.
- **4.5.3 `/wp-json/wp/v2/users`**: User enumeration via REST API.
  - Severity: P3 (user enum is valuable for further attacks).
- **4.5.4 `/wp-content/uploads/` directory listing**: Often reveals private docs.
- **4.5.5 `/xmlrpc.php`**: Enabled XML-RPC = brute force vector + amplification attack.
  - Severity: P3.
- **4.5.6 `/wp-admin/install.php`**: Reinstall page accessible = takeover.
  - Severity: P0.
- **4.5.7 `/wp-admin/setup-config.php`**: Setup wizard accessible = takeover.
- **4.5.8 Plugin/theme version detection**: Parse `/wp-content/plugins/<plugin>/readme.txt` for version, cross-ref CVE database.
- **4.5.9 `/?author=1`, `/?author=2`**: User enumeration via redirect to `/author/<username>`.

### 4.6 Symfony-specific
- **4.6.1 Symfony profiler**: `/_profiler`, `/_profiler/phpinfo`, `/_wdt/`
  - Severity: P1. Full request/response inspection in production = critical.
- **4.6.2 Symfony debug mode**: `/app_dev.php`, `/index_dev.php`
  - Severity: P1.

### 4.7 Drupal-specific
- **4.7.1 `/CHANGELOG.txt`**: Exposes Drupal core version.
- **4.7.2 `/sites/default/settings.php.bak`**, `/sites/default/files/private/`
- **4.7.3 `/user/register`**: Open registration when shouldn't be.
- **4.7.4 `/?q=user/register`**: Same via query.

### 4.8 Joomla-specific
- **4.8.1 `/administrator/`**: Admin login exposure.
- **4.8.2 `/configuration.php~`**, `/configuration.php-dist`

### 4.9 Magento-specific
- **4.9.1 `/app/etc/local.xml`**: DB credentials in plain XML.
- **4.9.2 `/downloader/`**: Magento downloader (RCE history).
- **4.9.3 `/RELEASE_NOTES.txt`**: Version disclosure.

---

## CATEGORY 5: JAVA / SPRING / TOMCAT EXPOSURES

### 5.1 Spring Boot Actuator endpoints
- **Detection paths** (try with and without `/actuator/` prefix):
  - `/actuator`, `/actuator/health`, `/actuator/info` (often public, low value)
  - `/actuator/env`, `/actuator/configprops` — exposes env vars and config (P1)
  - `/actuator/heapdump`, `/heapdump` — downloads JVM heap, contains secrets (P0)
  - `/actuator/threaddump`, `/dump` — thread state, may show passwords in stack
  - `/actuator/loggers` — POST allowed = log injection / DoS (P2)
  - `/actuator/mappings` — full route inventory
  - `/actuator/beans` — Spring bean inventory
  - `/actuator/trace`, `/actuator/httptrace` — recent HTTP traces with auth headers (P1)
  - `/actuator/shutdown` — POST shuts down app (P1)
  - `/actuator/restart` — restart trigger
  - `/actuator/refresh` — config refresh trigger
  - `/actuator/jolokia` — JMX over HTTP, often RCE (P0)
  - `/actuator/gateway/routes` — Spring Cloud Gateway routes
  - `/actuator/gateway/refresh` — gateway refresh
  - `/jolokia`, `/jolokia/list`
- **Validation**: JSON response with actuator-specific schema.
- **Severity**: Heapdump / Jolokia = P0. Env / trace = P1.
- **Chain**: Heapdump → extract credentials with `MemoryAnalyzer` → DB/cloud takeover.

### 5.2 Spring4Shell / Spring Cloud Function vulnerabilities
- **Detection**: Specific CVE checks (CVE-2022-22965, CVE-2022-22963).
- **Severity**: P0.

### 5.3 Tomcat manager
- **Detection**: `/manager/html`, `/manager/status`, `/host-manager/html`, `/manager/text/list`
- **Validation**: Basic auth challenge from Tomcat.
- **Default creds to try (one attempt only)**: `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret`, `admin:tomcat`, `tomcat:password`
- **Severity**: P0 if creds work (deploy WAR = RCE).

### 5.4 JBoss / WildFly
- **Detection**: `/jmx-console`, `/web-console`, `/admin-console`, `/jbossmq-httpil/`, `/jbossws/`, `/invoker/JMXInvokerServlet`, `/invoker/EJBInvokerServlet`
- **Severity**: P0 (RCE via JMX-Console deploy).

### 5.5 GlassFish
- **Detection**: `:4848/` (admin console), `/management/domain`
- **Default creds**: `admin:admin`, `admin:adminadmin`
- **Severity**: P0 with creds.

### 5.6 WebLogic
- **Detection**: `/console/login/LoginForm.jsp`, `/wls-wsat/CoordinatorPortType` (CVE-2017-10271), `/wls-wsat/RegistrationPortTypeRPC`, `/_async/AsyncResponseService`
- **Severity**: P0 (multiple known RCEs).

### 5.7 Java struts indicators
- **Detection**: `.action` extension, `.do` extension, `struts.xml` exposure.
- **Severity**: Triggers CVE-driven RCE checks (Struts2 RCEs are widespread).

### 5.8 Jetty
- **Detection**: `Server: Jetty` header, `/jetty/`, `/jolokia/`

---

## CATEGORY 6: EXPOSED ADMIN PANELS & MANAGEMENT INTERFACES

### 6.1 Jenkins
- **Detection**: `/`, `/login`, `/manage`, `/script` (Groovy script console = RCE), `/computer/`, `/asynchPeople/`, `/people/`, `/api/json`
- **Headers**: `X-Jenkins:` version header.
- **Anonymous read check**: Can `/api/json` be queried without auth?
- **Anonymous build check**: Can build be triggered? (Don't trigger; just check 403 vs 200 on `/job/<job>/build`)
- **Default creds**: `admin:admin`, `admin:password`, `jenkins:jenkins`
- **Severity**: Anonymous script console = P0. Anonymous build = P1.

### 6.2 GitLab
- **Detection**: `/users/sign_in`, `/help`, `/api/v4/version`, `/api/v4/projects`
- **Anonymous project listing** (when private should be required) = P2.
- **`/admin`** access = check.
- **GitLab CI runner registration token leak** in HTML = P2.

### 6.3 Gitea / Gogs
- **Detection**: `/explore/repos`, `/api/v1/version`
- **Open registration when shouldn't be**: `/user/sign_up`

### 6.4 phpMyAdmin
- **Detection paths**: `/phpmyadmin/`, `/pma/`, `/PMA/`, `/myadmin/`, `/mysql/`, `/sqladmin/`, `/dbadmin/`, `/db/`, `/admin/phpmyadmin/`, `/phpMyAdmin/`, `/phpmyadmin2/`, `/phpmyadmin3/`, `/phpmyadmin4/`
- **Validation**: HTML with phpMyAdmin branding.
- **Default creds**: `root:` (no password), `root:root`, `root:password`, `admin:admin`
- **Severity**: P0 with creds.

### 6.5 Adminer
- **Detection**: `/adminer.php`, `/adminer/`, `/_adminer.php`, `/db/adminer.php`
- **Severity**: P2 (exposed) to P0 (with creds).

### 6.6 phpPgAdmin
- **Detection**: `/phppgadmin/`, `/pgadmin/`
- **Default creds**: `postgres:postgres`, `postgres:password`

### 6.7 Grafana
- **Detection**: `/login`, `/api/health`, `/api/datasources`, `/d/` (dashboards), `/api/admin/users`
- **Anonymous access check**: Can `/api/dashboards/home` load without auth?
- **Default creds**: `admin:admin` (very common, often unchanged)
- **Known CVEs**: CVE-2021-43798 (path traversal), CVE-2024-9264 (SQL expression eval RCE)
- **Severity**: Anonymous data source listing = P2. Default creds = P1. Known CVE = P0.

### 6.8 Kibana
- **Detection**: `/app/kibana`, `/api/status`, `/login`
- **Anonymous access**: Can `/api/saved_objects/_find?type=dashboard` load?
- **Severity**: Open Kibana = P1 (sees all logs in attached Elasticsearch).
- **Known CVEs**: CVE-2019-7609 (RCE).

### 6.9 Elasticsearch
- **Detection**: Port 9200 (default). `GET /` returns version JSON. `GET /_cat/indices`, `GET /_cluster/health`
- **Anonymous access**: Can index list be retrieved?
- **Severity**: Open ES with prod data = P0.

### 6.10 RabbitMQ Management
- **Detection**: `:15672/`, `/api/overview`, `/api/whoami`
- **Default creds**: `guest:guest` (only works from localhost in modern versions, but check)
- **Severity**: P1 with creds.

### 6.11 Apache Spark UI
- **Detection**: `:8080/` (master UI), `:4040/` (job UI), `/jobs/`, `/stages/`
- **REST API**: `:6066/v1/submissions/` — submit-job = RCE if exposed.
- **Severity**: Spark REST submission = P0.

### 6.12 Apache Airflow
- **Detection**: `/admin/`, `/login/`, `/api/v1/dags`, `/health`
- **Default creds**: `airflow:airflow`, `admin:admin`
- **Anonymous DAG trigger** = P0.
- **Known CVEs**: many.

### 6.13 Apache Solr
- **Detection**: `:8983/solr/`, `/solr/admin/cores`, `/solr/admin/info/system`
- **Known CVEs**: CVE-2019-17558 (Velocity template RCE), CVE-2021-27905
- **Severity**: P0 for known RCEs.

### 6.14 HashiCorp Vault
- **Detection**: `/v1/sys/health`, `/v1/sys/seal-status`
- **Validation**: `sealed: false` + open API = catastrophic.
- **Severity**: Unsealed Vault = P0.

### 6.15 HashiCorp Consul
- **Detection**: `:8500/v1/status/leader`, `/v1/agent/self`, `/ui/`
- **Anonymous KV access**: `/v1/kv/?recurse=true` lists all KV (often secrets).
- **Severity**: P0 with KV exposure.

### 6.16 etcd
- **Detection**: `:2379/v2/keys/`, `:2379/version`, `:2379/v3/kv/range`
- **Anonymous access**: Many etcd instances exposed without auth.
- **Severity**: P0 (Kubernetes secrets, infra config).

### 6.17 Redis
- **Detection**: Port 6379. `INFO` command returns version.
- **Anonymous access**: `INFO server`, `KEYS *`
- **Severity**: Open Redis = P1-P0 depending on contents. Modern Redis (>=6) requires ACL by default but many deploys disable.
- **RCE chain**: SSH key write via Redis to `/root/.ssh/authorized_keys` (classic).

### 6.18 Memcached
- **Detection**: Port 11211. `stats` command.
- **Severity**: P2-P1 (cache contents may include session tokens).

### 6.19 MongoDB
- **Detection**: Port 27017. `db.runCommand({connectionStatus:1})`.
- **Severity**: Open MongoDB with data = P0.

### 6.20 CouchDB
- **Detection**: `:5984/`, `/_all_dbs`, `/_users/_all_docs`
- **Default creds**: `admin:admin`
- **Severity**: P0.

### 6.21 Cassandra / ScyllaDB
- **Detection**: Port 9042 (CQL), `/jmx-console` if enabled.

### 6.22 Hadoop / HDFS
- **Detection**: `:50070/` (NameNode UI), `:8088/` (ResourceManager UI), `:9870/`
- **Severity**: P1-P0. ResourceManager often allows job submission = RCE.

### 6.23 ZooKeeper
- **Detection**: Port 2181. `stat`, `mntr`, `conf` four-letter commands.
- **Severity**: P2-P1.

### 6.24 Portainer (Docker management)
- **Detection**: `:9000/`, `/api/status`, `/api/endpoints`
- **Setup wizard not completed**: `/api/users/admin/check` returns 404 = takeover possible (P0).
- **Default creds**: `admin:portainer`
- **Severity**: P0 if setup-incomplete or with creds.

### 6.25 Rancher
- **Detection**: `/v3/`, `/login`
- **Default creds**: `admin:admin` (older versions).

### 6.26 Kubernetes Dashboard
- **Detection**: `/`, `/api/v1/login`, `/api/v1/csrftoken/login`
- **Skip-auth check**: Some deploys allow anonymous "skip" login = P0.

### 6.27 Docker registry
- **Detection**: `:5000/v2/`, `/v2/_catalog`
- **Anonymous catalog list**: P2-P1 (image enumeration → tag enumeration → image pull → secret extraction).

### 6.28 Docker Swarm / Docker API
- **Detection**: `:2375/version`, `:2376/` (TLS), `/containers/json`, `/info`
- **Anonymous Docker API on 2375**: P0 (full container/host control).

### 6.29 Kubernetes API
- **Detection**: `:6443/`, `:8080/` (legacy insecure), `/api/v1/namespaces`, `/api/v1/secrets`
- **Anonymous access**: P0.

### 6.30 OpenShift
- **Detection**: `:8443/console`, `/oapi/v1/`

### 6.31 Webmin
- **Detection**: `:10000/`, header `Server: MiniServ`
- **Default creds**: `root:` system password, `admin:admin`
- **Known RCEs**: CVE-2019-15107.

### 6.32 cPanel / WHM
- **Detection**: `:2082/`, `:2083/`, `:2086/`, `:2087/`
- **Severity**: Login pages alone = informational; bypass / leaked tokens = P0.

### 6.33 Plesk
- **Detection**: `:8443/`, `/login_up.php3`

### 6.34 DirectAdmin
- **Detection**: `:2222/CMD_LOGIN`

### 6.35 ISPConfig / Virtualmin / various hosting panels
- Standard footprints, default-cred attempts.

### 6.36 PiHole admin
- **Detection**: `/admin/`, `/admin/index.php`
- **Default creds**: blank, or set during install.

### 6.37 OctoPrint, Home Assistant, OpenHAB (IoT panels)
- Not bounty-relevant typically, but appear on broad scans.

### 6.38 Plex / Jellyfin / Emby
- Open with default install = P3-P2 (data exposure).

### 6.39 NetData
- **Detection**: `:19999/`, `/api/v1/info`
- **Severity**: P3 (system metric disclosure can aid recon).

### 6.40 Zabbix
- **Detection**: `/zabbix/`, `/zabbix.php?action=dashboard.view`
- **Default creds**: `Admin:zabbix`
- **Known CVEs**: CVE-2022-23131, CVE-2024-22116.

### 6.41 Nagios
- **Detection**: `/nagios/`, `/cgi-bin/nagios/`
- **Default creds**: `nagiosadmin:nagiosadmin`
- **Known CVEs**: many in Nagios XI.

### 6.42 Icinga
- **Detection**: `/icinga/`, `/icingaweb2/`

### 6.43 Prometheus
- **Detection**: `:9090/`, `/api/v1/status/config`, `/api/v1/targets`
- **Severity**: Open Prometheus = P2-P1 (config disclosure includes scrape endpoints, sometimes credentials in URLs).

### 6.44 Alertmanager
- **Detection**: `:9093/`, `/api/v2/status`
- **Severity**: P2.

### 6.45 Argo CD
- **Detection**: `/api/version`, `/swagger-ui`
- **Default creds**: Initial admin password = base64 of internal pod name (CVE-2020-8828).
- **Severity**: P1-P0.

### 6.46 Argo Workflows
- **Detection**: `/api/v1/workflows`
- **Anonymous workflow submission** = RCE (P0).

### 6.47 Flux CD
- **Detection**: less direct UI; check for Flux-managed manifests.

### 6.48 Spinnaker
- **Detection**: `/gate/health`, `/deck/`

### 6.49 Harbor (container registry)
- **Detection**: `/api/v2.0/health`, `/api/v2.0/projects`
- **Anonymous project listing**: P2.

### 6.50 Nexus Repository / Artifactory
- **Detection**: `/service/rest/v1/status`, `/artifactory/api/system/ping`
- **Default creds**: `admin:admin123` (Nexus), `admin:password` (Artifactory)
- **Anonymous browse** check.

### 6.51 SonarQube
- **Detection**: `/api/system/status`, `/api/users/search`
- **Default creds**: `admin:admin`
- **Severity**: P1 (source code analysis exposure, including secrets found in scans).

### 6.52 Mattermost / Rocket.Chat / self-hosted chat
- **Open registration** when shouldn't be = P3-P2.
- **Channel listing** without auth = P3.

### 6.53 Discourse
- **Detection**: `/admin`, `/site.json`

### 6.54 Bitbucket Server / Bamboo
- **Detection**: `/status`, `/rest/api/latest/`
- **Known CVEs** for older Bitbucket.

---

## CATEGORY 7: NETWORK SERVICES & PROTOCOLS

### 7.1 SSH (port 22)
- **Detection**: Banner grab. Check version for known CVEs (e.g., CVE-2024-6387 regreSSHion).
- **No bounty value alone** unless combined with leaked private key.

### 7.2 FTP (port 21)
- **Anonymous FTP**: try `anonymous:anonymous@`, list directory.
- **Severity**: P3-P1 depending on contents.

### 7.3 Telnet (port 23)
- **Detection**: Banner.
- **Severity**: Existence alone may be reportable as misconfig (P4-P3).

### 7.4 SMB (port 445)
- **Anonymous shares**: enum shares with `smbclient -L`.
- **Severity**: P2 (file disclosure), P0 (writable share leading to LPE not bounty-relevant typically).

### 7.5 RDP (port 3389)
- **Detection**: NLA enabled?
- **Severity**: Existence alone usually informational; weak creds via brute force NOT in scope for most programs.

### 7.6 LDAP (389, 636)
- **Anonymous bind**: can directory be enumerated?
- **Severity**: P2-P1 (full user/group enumeration including emails, sometimes passwords).

### 7.7 SNMP (UDP 161)
- **Default community strings**: `public`, `private`
- **Severity**: P3-P1 (system info disclosure, sometimes write access).

### 7.8 NFS (port 2049)
- **Detection**: `showmount -e`
- **Anonymous-readable exports**: file disclosure.

### 7.9 rsync (port 873)
- **Detection**: `rsync <host>::` lists modules.
- **Anonymous module listing/reading**: P2-P1.

### 7.10 SMTP open relay
- **Detection**: Try sending mail through it to attacker-controlled address.
- **Severity**: P3-P1.

### 7.11 DNS open recursion / zone transfer
- **Zone transfer (AXFR)**: `dig axfr @<ns> <domain>`
- **Severity**: AXFR = P3 (full subdomain enumeration).

### 7.12 NTP misconfiguration
- **Mode 6/7 amplification potential**.
- **Bounty value low**, mostly informational.

### 7.13 Memcached UDP amplification (port 11211 UDP)
- Known DDoS reflector.
- **Severity**: P2 in some programs.

### 7.14 Kerberos (port 88)
- AS-REP roasting potential if exposed.

### 7.15 RPC (port 111, 135)
- **Information disclosure** via `rpcinfo`.

---

## CATEGORY 8: CLOUD-PROVIDER MISCONFIGURATIONS (External Vantage)

### 8.1 AWS S3 buckets
- **Detection method 1 — direct discovery**: try `<company>.s3.amazonaws.com`, `<company>-<word>.s3.amazonaws.com` with permutations.
- **Detection method 2 — enumeration via JS bundles**: parse JS files for S3 URLs.
- **Detection method 3 — DNS CNAMEs** pointing to `s3.amazonaws.com`.
- **Tests** (in priority):
  - `GET /` (listing): `<ListBucketResult>` XML response = public list.
  - `GET /<known-file>`: object public read.
  - `PUT /poc.txt`: writable bucket (DON'T do this without permission).
  - ACL read: `?acl`
- **Severity**: Public list of private bucket = P2-P1. Writable = P1-P0.

### 8.2 AWS S3 subdomain takeovers
- CNAME pointing to non-existent bucket = takeover.
- **Severity**: P1-P0 (depending on subdomain trust).

### 8.3 AWS CloudFront subdomain takeovers
- CNAME to deleted distribution = takeover.

### 8.4 AWS Elastic Beanstalk takeovers
- Pattern: `*.elasticbeanstalk.com` no longer claimed.

### 8.5 GCP Cloud Storage
- **Detection**: `storage.googleapis.com/<bucket>/`, `<bucket>.storage.googleapis.com/`
- Anonymous list / read tests.

### 8.6 Azure Blob Storage
- **Detection**: `<account>.blob.core.windows.net/<container>/`
- Anonymous container listing.

### 8.7 Subdomain takeover (general)
- CNAMEs pointing to dangling resources at: AWS S3, AWS CloudFront, GitHub Pages, Heroku, Shopify, Tumblr, WordPress.com, Squarespace, Fastly, Pantheon, Zendesk, Helpscout, Intercom, Statuspage, Surge, Bitbucket Pages, Read the Docs, Ghost.io, Netlify, Vercel (formerly Zeit), Webflow, Cargo, Strikingly, Brightcove, Wishpond, Tilda, UserVoice, MyShopify (legacy), Smartling, Acquia, AfterShip, Aha!, Anima, Apigee, Bigcartel, Brightcove, Cargocollective, Cloudfront, Desk, Frontify, Getresponse, Gitbook, Helpjuice, Help Scout, Hubspot, Jetbrains Space, Kinsta, LaunchRock, Mashery, Pingdom, Proposify, Readme.io, S3, ServiceNow, Shopify, ShortIO, Simplebooklet, Smugmug, Statuspage, Strikingly, Surveygizmo, Tave, Teamwork, Tictail, Unbounce, Uptimerobot, Webflow, WishpondV2, Wix, Wpengine, Worksites, etc. — **see can-i-take-over-xyz** for the maintained list with fingerprints.
- **Validation**: Confirm dangling by checking the documented "available for takeover" response per provider.
- **Severity**: P1-P0 depending on subdomain trust. Apex-trusted subdomain = P0.

### 8.8 Cloud metadata endpoints (when reachable via SSRF — passive detection here)
- AWS: `169.254.169.254/latest/meta-data/`, IMDSv1 enabled (no token required) = vulnerable.
- GCP: `metadata.google.internal/computeMetadata/v1/`
- Azure: `169.254.169.254/metadata/instance?api-version=2021-02-01`
- Detection of reachability requires SSRF; we identify SSRF surface separately.

### 8.9 Cloud-specific service exposure
- **AWS Elastic Search service**, **AWS RDS** publicly accessible, **AWS DocumentDB**.
- Detection: hostname patterns + open ports.

### 8.10 Firebase databases
- **Detection**: `<project>.firebaseio.com`, `<project>-default-rtdb.firebaseio.com/.json`
- **Validation**: GET `/.json` returning data = world-readable.
- **Severity**: P1-P0.
- **Write check**: PUT (don't do without authorization).

### 8.11 Firestore / Firebase rules misconfig
- Default `allow read, write: if true` rules.

### 8.12 Cloudflare R2 / DO Spaces / Backblaze B2
- Same patterns as S3. Public bucket misconfig.

### 8.13 Heroku app takeover
- Apps no longer maintained but DNS still points.

---

## CATEGORY 9: API & SERVICE DOCUMENTATION EXPOSURE

### 9.1 Swagger/OpenAPI
- **Detection paths**: `/swagger`, `/swagger.json`, `/swagger.yaml`, `/swagger/v1/swagger.json`, `/swagger-ui.html`, `/swagger-ui/`, `/api/swagger`, `/api/swagger.json`, `/api/docs`, `/api-docs`, `/v1/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/openapi.yaml`, `/redoc`, `/rapidoc`, `/docs`, `/api/v1/docs`
- **Validation**: JSON with `swagger:` or `openapi:` key, or HTML with Swagger-UI branding.
- **Severity**: P3 alone (informational), P2-P1 if internal/admin endpoints documented or sensitive.
- **Use**: Feed enumerated endpoints back into the crawler.

### 9.2 GraphQL
- **Detection**: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/api/query`
- **Introspection enabled**: POST `{"query":"{__schema{types{name}}}"}` returns schema = P3 (informational, sometimes P2 if schema reveals admin mutations).
- **Other GraphQL issues**: depth attacks, alias batching, field suggestions enabled, CSRF on mutations.

### 9.3 SOAP / WSDL
- **Detection**: `?wsdl`, `?WSDL`, `/services/`, paths ending `.asmx?wsdl`
- **Severity**: P3-P2.

### 9.4 RPC endpoints
- gRPC reflection enabled, JSON-RPC introspection.

### 9.5 Postman collections leaked
- Look for `.postman_collection.json` paths and Postman public workspaces under company name.

### 9.6 Insomnia / Bruno collections
- Similar.

---

## CATEGORY 10: SECURITY HEADERS & TLS MISCONFIGURATIONS

These are usually **informational** on bounty programs but worth noting because some chain into real bugs.

### 10.1 Missing security headers (informational unless chained)
- `Strict-Transport-Security` missing
- `Content-Security-Policy` missing or `unsafe-inline`
- `X-Frame-Options` missing (clickjacking demonstration sometimes pays)
- `X-Content-Type-Options` missing

### 10.2 CORS misconfigurations (often pays)
- **Origin reflection**: `Access-Control-Allow-Origin: <attacker.com>` with `Allow-Credentials: true` = P1.
- **Null origin allowed**: `Access-Control-Allow-Origin: null`
- **Wildcard with credentials**: invalid combo but some servers accept.
- **Validation**: Send origin headers, observe ACAO reflection.
- **Severity**: P2-P1 if reflective with credentials and authenticated endpoint.

### 10.3 TLS issues (low bounty value, document for completeness)
- Self-signed cert on production.
- Expired cert.
- Weak ciphers (RC4, DES).
- SSL/TLS protocols < 1.2.
- Heartbleed (CVE-2014-0160) — vanishingly rare now but check.
- ROBOT, DROWN, POODLE, BEAST, CRIME, BREACH (mostly historical).
- Cert chain issues.

### 10.4 HTTP methods misconfigurations
- `OPTIONS` returning `TRACE`, `PUT`, `DELETE` enabled.
- `PUT` to arbitrary path = file upload (P0 if writable web root).
- `TRACE` enabled = XST historical.

### 10.5 HTTP/2, HTTP/3 specific
- Request smuggling via H2 downgrade (CL.0, H2.CL, H2.TE).

---

## CATEGORY 11: KNOWN CVE-DRIVEN DETECTIONS (Highest-Value Category)

This is where Nuclei's template corpus shines. Maintain a local mirror of `projectdiscovery/nuclei-templates` and run the `cves/`, `vulnerabilities/`, `exposed-panels/`, `exposures/`, `misconfiguration/`, `default-logins/`, `takeovers/` directories.

### 11.1 Top recurring CVE classes to prioritize
- Spring Framework (Spring4Shell, Spring Cloud Function, etc.)
- Apache Struts2 (multiple ongoing)
- Confluence (CVE-2022-26134, CVE-2023-22515, CVE-2023-22518)
- Jira (CVE-2022-0540, CVE-2021-26086)
- Bitbucket (CVE-2022-43781, CVE-2022-26133)
- GitLab (multiple, especially CVE-2021-22205 ExifTool)
- Citrix ADC / Gateway (CVE-2019-19781, CVE-2023-3519, CVE-2023-4966 Citrix Bleed)
- F5 BIG-IP (CVE-2022-1388, CVE-2023-46747)
- Fortinet FortiOS (CVE-2022-40684, CVE-2023-27997)
- Pulse Secure (CVE-2019-11510, CVE-2020-8260)
- Ivanti (CVE-2023-46805, CVE-2024-21887, CVE-2024-21893)
- Microsoft Exchange (ProxyShell, ProxyLogon, ProxyNotShell)
- Log4Shell (CVE-2021-44228) — surface still appears
- VMware vCenter (CVE-2021-21972, CVE-2021-21985)
- WordPress plugins (WPScan database integration)
- Drupal (Drupalgeddon series)
- Magento (multiple)
- Jenkins (CVE-2024-23897 read-arbitrary-file)
- GeoServer, GeoNode (CVE-2024-36401)
- Adobe ColdFusion (CVE-2023-26360, CVE-2024-20767)
- WS_FTP (CVE-2023-40044)
- MOVEit Transfer (CVE-2023-34362)
- Atlassian Bamboo
- Exim, Sendmail historical
- Cisco IOS XE (CVE-2023-20198)
- CrushFTP (CVE-2024-4040)

### 11.2 Detection workflow
- Fingerprint product + version (banner / favicon hash / response signature / static asset hash).
- Look up product/version in CVE DB → list of applicable CVEs.
- Run safe-verification template for each. SAFE = no exploitation, just version-confirmed presence.

---

## CATEGORY 12: AUTHENTICATION & SESSION MISCONFIGURATIONS

### 12.1 JWT issues
- **Algorithm `none`**: change `alg` to `none`, remove signature, retry.
- **Weak HMAC secrets**: try common secrets (`secret`, `Secret123`, `your-256-bit-secret`, etc.) against captured tokens.
- **`kid` injection**: SQL injection in `kid` header, path traversal in `kid`.
- **JWKS spoofing**: `jku` pointing to attacker-controlled host.
- **Algorithm confusion**: RS256 → HS256 with public key as HMAC secret.
- **Severity**: P1-P0 (auth bypass).

### 12.2 OAuth/OIDC misconfigurations
- **Open redirect in `redirect_uri`**: `https://target/oauth/authorize?redirect_uri=https://attacker.com`
- **PKCE not enforced** (mobile/SPA flows): code interception.
- **State parameter not enforced**: CSRF on OAuth.
- **`response_type=token` in confidential client**: token leak via fragment.
- **Account takeover via OAuth provider mismatch** (different IdPs, same email).
- **Pre-account hijack** (claim email before victim creates account).

### 12.3 Session cookie issues
- Missing `Secure`, `HttpOnly`, `SameSite` on auth cookies.
- Session ID predictability.
- Session fixation possible.

### 12.4 Default credentials (extensive list — see CATEGORY 6 throughout)
- Maintain a curated list per detected product.
- Try ONE login attempt per product/credential pair, then stop. Brute force = legal risk.

### 12.5 Forgotten password flow weaknesses
- Token in URL with no expiry.
- Token reusable.
- Token predictable (sequential, time-based).
- User enumeration via response timing or message difference.

### 12.6 2FA bypass patterns
- 2FA endpoint accepts any code if user state is "pending verification."
- 2FA can be skipped via parameter manipulation.
- Recovery codes brute-forceable.
- Race conditions on 2FA.

### 12.7 Account lockout missing
- No rate limit on login = credential stuffing risk.

### 12.8 Sign-up race conditions
- Sign-up with same email twice in parallel.

---

## CATEGORY 13: WEB APPLICATION VULNERABILITIES (Brief — Often Out of "Misconfig" Scope)

The categories below are full vulnerability classes, not pure misconfigurations. Listed for completeness; depth handled by separate detection modules.

### 13.1 SQL injection
- Error-based, time-based, boolean-based, union-based.
- Detection via parameterized payload battery; verification via deterministic side channel.

### 13.2 NoSQL injection
- MongoDB operator injection, CouchDB injection.

### 13.3 Server-Side Request Forgery (SSRF)
- Detection via OOB collaborator (Interactsh-style self-host).
- Cloud metadata endpoint reachability test.

### 13.4 Server-Side Template Injection (SSTI)
- Engine fingerprint (Jinja2, Twig, FreeMarker, Velocity, Smarty, Handlebars, ERB, Thymeleaf, Mustache).
- Engine-specific verification payloads.

### 13.5 Local File Inclusion / Remote File Inclusion (LFI/RFI)
- Path traversal: `../../../etc/passwd`, `..\..\..\windows\win.ini`, encoded variants, null byte (`%00`), filter wrappers (`php://filter/convert.base64-encode/resource=`).

### 13.6 Cross-Site Scripting (XSS)
- Reflected, stored, DOM-based.
- Verification via headless browser.

### 13.7 XML External Entity (XXE)
- DTD declaration in XML payload, OOB exfiltration.

### 13.8 Insecure deserialization
- Java (ysoserial), .NET (ysoserial.net), PHP (PHPGGC), Python (pickle), Ruby (Marshal).

### 13.9 HTTP Request Smuggling
- CL.TE, TE.CL, TE.TE, H2.CL, H2.TE.

### 13.10 Web Cache Poisoning / Cache Deception
- Header-based poisoning, path-based deception.

### 13.11 Prototype Pollution
- Client-side and server-side.

### 13.12 Race conditions
- TOCTOU on auth, payment double-spend, coupon re-use, etc.

### 13.13 IDOR (Insecure Direct Object Reference)
- Sequential ID enumeration with auth context tests.

### 13.14 Mass assignment / Parameter pollution
- Unexpected parameter acceptance.

### 13.15 Command injection
- Shell metacharacter injection in user-controlled values.

### 13.16 Open redirect
- Often low-bounty alone; chains into OAuth attacks etc.

### 13.17 CSRF
- Missing token, weak token, predictable token.

### 13.18 CORS misconfiguration (already in Cat 10).

---

## CATEGORY 14: SECRETS-IN-PUBLIC-CONTENT

### 14.1 Secrets in JS bundles
- Parse all served JS files for credential patterns (regex + entropy).
- Look in source maps where present.

### 14.2 Secrets in HTML comments
- `<!-- TODO: hardcode this for now: api_key=... -->`

### 14.3 Secrets in error pages
- Stack traces with DB connection strings, API keys.

### 14.4 Secrets in mobile app metadata
- (Out of scope for HTTP-only scanner, but APK/IPA decompilation finds tons.)

### 14.5 Secrets in public Git history
- GitHub search: `org:<target> password`, `org:<target> api_key`, etc.
- TruffleHog / Gitleaks against discovered repos.

### 14.6 Secrets in Pastebin / Github Gists / public paste sites
- Periodic search for company name + secret patterns.

### 14.7 Secret patterns to detect (curated list, prioritized by validatability)
- AWS access keys: `AKIA[0-9A-Z]{16}` (validate via STS GetCallerIdentity)
- AWS secret keys: 40-char base64-ish (paired with access key)
- AWS session tokens
- GCP service account keys (JSON with `private_key`)
- GCP API keys: `AIza[0-9A-Za-z-_]{35}` (validate via maps API call cost-free)
- Azure storage account keys
- Slack tokens: `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` (validate via auth.test)
- Slack webhooks: `https://hooks.slack.com/services/T...`
- GitHub PAT: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` (validate via API user endpoint)
- GitHub App tokens: `ghs_`
- GitLab PAT: `glpat-`
- Bitbucket app passwords
- npm tokens: `npm_`
- PyPI tokens: `pypi-`
- Stripe keys: `sk_live_`, `pk_live_`, `rk_live_` (validate via balance endpoint, read-only)
- Stripe webhook signing secrets
- SendGrid: `SG.`
- Mailgun keys
- Twilio: `SK`, `AC` followed by 32 hex
- PayPal client secrets
- Square access tokens
- Shopify: `shpss_`, `shpat_`, `shpca_`, `shppa_`
- Mailchimp: `[a-f0-9]{32}-us[0-9]{1,2}`
- Algolia keys
- Firebase: see CATEGORY 8.10
- HuggingFace: `hf_`
- OpenAI: `sk-`, `sk-proj-`
- Anthropic: `sk-ant-`
- Cohere, Replicate, Together, Groq, Perplexity, Mistral keys
- Datadog API keys
- New Relic
- PagerDuty
- Linear API tokens
- Notion integration tokens: `secret_`
- Atlassian API tokens
- Jira tokens
- ServiceNow OAuth tokens
- Salesforce session tokens
- DigitalOcean PAT: `dop_v1_`
- Heroku API keys
- Vercel tokens
- Netlify tokens
- Cloudflare API tokens / global API key
- DNSimple, Linode, Vultr, Hetzner API keys
- SSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`)
- PGP private keys
- JWT signing keys
- Bcrypt/Argon hashes (informational)
- Generic high-entropy strings (with high false-positive rate, lowest priority)

### 14.8 Validation strategy per secret type
- Always use **read-only / cost-free** validation endpoints.
- Cache validation results (don't re-validate the same key).
- Inform the affected party immediately when a live key is detected.
- Document the validation request in evidence (full request shown to customer).

---

## CATEGORY 15: AI / ML INFRASTRUCTURE EXPOSURES (Modern Surface)

### 15.1 Vector databases (unauthenticated)
- **Qdrant**: `:6333/collections`, `:6333/cluster`, `:6333/telemetry`
- **Weaviate**: `:8080/v1/meta`, `:8080/v1/schema`
- **Milvus**: gRPC `:19530` + REST `:9091`
- **Chroma**: `:8000/api/v1/heartbeat`, `:8000/api/v1/collections`
- **pgvector** in exposed Postgres.
- **Pinecone**: cloud only, but leaked API keys grant access.
- **Severity**: P2-P1.

### 15.2 LLM serving infrastructure
- **vLLM**: `/v1/models`, `/v1/chat/completions` exposed without auth.
- **Ollama**: `:11434/api/tags` (model list), `:11434/api/generate` (free inference).
- **LocalAI, LM Studio, Text Generation WebUI** open ports.
- **LiteLLM proxy** without auth.
- **OpenAI-compatible proxies** (LangChain LangServe, FastChat, etc.).

### 15.3 LangChain / LangServe / LangGraph endpoints
- `/invoke`, `/stream`, `/batch`, `/playground`
- Detection via response signature.

### 15.4 LlamaIndex serving
- Similar patterns.

### 15.5 MCP servers exposed
- JSON-RPC schema, `tools/list` returns tool inventory.
- Often deployed without any auth on the assumption "it's only for local use."

### 15.6 AI plugin manifests
- `/.well-known/ai-plugin.json` (ChatGPT plugins)
- Manifest reveals internal endpoints.

### 15.7 Model file exposure
- File extensions in publicly-listable storage: `.pt`, `.pth`, `.safetensors`, `.gguf`, `.onnx`, `.bin`, `.ckpt`, `.h5`, `.pb`, `.tflite`, `.mlmodel`
- Often embedded into Docker images that get pushed to public registries.

### 15.8 Jupyter / Zeppelin / RStudio Server
- **Jupyter**: `:8888/`, no token required = RCE (P0).
- **Zeppelin**: `:8080/`, anonymous notebooks executable.
- **RStudio Server**: `:8787/`, default creds.

### 15.9 MLflow
- **Detection**: `:5000/`, `/api/2.0/mlflow/experiments/list`
- Anonymous access common.

### 15.10 Kubeflow
- Component-specific exposures.

### 15.11 Weights & Biases self-hosted
- Internal deployment exposures.

### 15.12 Hugging Face Spaces / leaked HF tokens
- Standard secret pattern.

### 15.13 ChatGPT actions / Claude tools / function-calling endpoints
- Misconfigured CORS allows browser-based abuse.
- Tools accepting arbitrary URLs (SSRF) or filesystem paths.

### 15.14 RAG ingestion endpoints
- Public document submission endpoint = RAG poisoning surface.

---

## CATEGORY 16: MOBILE & API GATEWAY EXPOSURES

### 16.1 Mobile API endpoints
- `/api/v1/`, `/api/mobile/`, `/m/api/`, `/mobile/api/`
- Often missing auth checks present in web flow (assuming "no one will hit this directly").

### 16.2 API gateways
- AWS API Gateway with no auth + CORS open.
- Kong / Tyk admin APIs exposed.

### 16.3 GraphQL via mobile
- Mobile-only schemas with extra mutations.

### 16.4 gRPC services exposed
- Reflection enabled = full service enumeration.

---

## CATEGORY 17: CDN & EDGE MISCONFIGURATIONS

### 17.1 Origin server bypassing CDN
- Direct origin IP discoverable via historical DNS, certificate transparency, Shodan.
- Origin doesn't validate `Host` header → request smuggling/cache attacks.

### 17.2 Cloudflare bypass via misconfigured origin
- Origin accepts requests not coming from CF IPs.

### 17.3 Cache key issues
- Auth headers not in cache key = response from one user cached for another.

### 17.4 Edge worker misconfigurations
- Cloudflare Workers, Lambda@Edge, Fastly Compute@Edge with logic bugs.

---

## CATEGORY 18: BUSINESS-LOGIC ADJACENT MISCONFIGURATIONS

These straddle "misconfiguration" and "business logic." Listed for completeness.

### 18.1 Privilege escalation via missing auth on admin endpoints
- `/admin/*` accessible without proper role check.
- `/api/admin/*` likewise.

### 18.2 Tenant isolation bugs
- Object IDs work across tenant boundaries.

### 18.3 Webhook endpoints with no auth
- `/webhook/<provider>` accepts arbitrary POST.
- Allows abuse / amplification.

### 18.4 File upload without validation
- Type, size, contents.

### 18.5 Email-based account-takeover patterns
- Pre-registration, email change without re-confirm, etc.

### 18.6 Pricing / promo code abuse
- Stacking, negative quantities, currency confusion.

### 18.7 Race conditions in transactional flows
- Coupon, balance, vote, etc.

---

## CATEGORY 19: DEVOPS / SUPPLY CHAIN EXPOSURES

### 19.1 Internal package registry exposure
- Private NPM registry, private PyPI, internal Maven, Nexus repository.

### 19.2 Dependency confusion attack surface
- Internal package names visible in public configs (package.json, requirements.txt).

### 19.3 SCM (Bitbucket / GitLab / Gitea) admin endpoints
- See CATEGORY 6.

### 19.4 CI runner exposure
- GitLab Runner registration tokens.
- Self-hosted GitHub Actions runner endpoints.

### 19.5 Build artifact storage exposure
- Internal Artifactory / Nexus with anonymous read.

### 19.6 Secret scanning bypasses
- Repos with secrets that GitHub didn't catch (custom patterns, base64, gzipped).

### 19.7 Slack / Discord webhook exposure
- Often hardcoded in client-side JS.

### 19.8 PagerDuty / Opsgenie integration tokens
- In CI configs or client JS.

---

## CATEGORY 20: MISCELLANEOUS HIGH-VALUE ODDITIES

### 20.1 `crossdomain.xml` / `clientaccesspolicy.xml` overly permissive
- Allows Flash / Silverlight cross-domain.

### 20.2 `robots.txt` revealing sensitive paths
- Informational; sometimes lists `/admin`, `/internal/`, `/staging/`.

### 20.3 `sitemap.xml` revealing private content
- URLs not meant to be indexed.

### 20.4 `security.txt` (positive — its presence is good).

### 20.5 `humans.txt`, `BingSiteAuth.xml`, `google*.html`, `pinterest-*.html`
- Verification files; lower priority but worth fingerprinting.

### 20.6 `composer.json`, `package.json`, `requirements.txt`, `Gemfile.lock`, `Cargo.lock`, `go.mod`, `pom.xml`, `pyproject.toml`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Dependency disclosure → CVE targeting.

### 20.7 `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
- Informational only.

### 20.8 `.well-known/` paths (variable value)
- `/.well-known/security.txt`
- `/.well-known/acme-challenge/`
- `/.well-known/openid-configuration`
- `/.well-known/oauth-authorization-server`
- `/.well-known/apple-app-site-association` (universal links — reveals iOS app paths)
- `/.well-known/assetlinks.json` (Android)
- `/.well-known/dnt-policy.txt`
- `/.well-known/change-password`
- `/.well-known/host-meta`
- `/.well-known/webfinger`
- `/.well-known/matrix/client`, `/.well-known/matrix/server` (Matrix homeserver)
- `/.well-known/nostr.json`
- Many others.

### 20.9 Exposed `/server-status`, `/server-info` (Apache mod_status)
- Reveals all in-flight requests = session token leakage.
- **Severity**: P1 if traffic is sensitive.

### 20.10 Nginx `/nginx_status`
- Less data than Apache but still informational.

### 20.11 IIS-specific
- `/iisstart.htm`, `/welcome.png`, `/iis-85.png` (default install page, server fingerprint).
- `~1` short-name disclosure (CVE-2010-2731 era, still affects some).

### 20.12 PHPUnit RCE (`/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`)
- CVE-2017-9841, still appears in old shared hosting.
- **Severity**: P0 RCE.

### 20.13 Old framework / library specific
- ZendFramework `/zf-version`
- Symfony `/_fragment`
- Flask `/console` (Werkzeug debugger), `/debug`
- Django debug page
- Rails Web Console (CVE-2014-3514)
- Sinatra error pages
- Express `X-Powered-By`

### 20.14 Server-Sent Events / WebSocket endpoints
- Exposed without auth.

### 20.15 Internal IPs in headers / responses
- `X-Forwarded-For` reflection, internal IPs in error pages, stack traces.

### 20.16 Email server admin panels
- Postfix admin, MailEnable, hMailServer, Mailcow.

### 20.17 VPN admin panels
- OpenVPN-AS, WireGuard UIs, SoftEther, Pritunl.

### 20.18 Network device management
- MikroTik Winbox, Ubiquiti UniFi controller, pfSense webConfigurator, OPNsense.

### 20.19 Industrial control system protocols (ICS/SCADA)
- Modbus (502), DNP3 (20000), S7 (102), BACnet (47808).
- Legal note: scanning these can be regulated. Check program scope carefully.

### 20.20 Game server administration
- Minecraft RCON, source-engine-RCON, Battle.net dev portals.

### 20.21 Jitsi, Matrix, BigBlueButton admin endpoints
- Many self-hosted instances expose admin panels.

### 20.22 Self-hosted email providers (Mailcow, Mail-in-a-Box, iRedMail)
- Default-creds risk on admin UIs.

### 20.23 Bitwarden / Vaultwarden self-hosted
- Admin panel: `/admin/`. Default token in env, often unset.

### 20.24 Nextcloud / ownCloud
- `/status.php` reveals version.
- Many CVEs.

### 20.25 Synology DSM, QNAP, TrueNAS web UIs
- Often exposed by accident, default creds.

### 20.26 IPMI / iDRAC / iLO / IMM web interfaces
- `:443/` with vendor-specific default creds.
- Critical infra (out-of-band management).

### 20.27 Confluence / Jira public instances
- Misconfigured anonymous access to internal spaces.

### 20.28 Power BI / Tableau / Looker public reports
- Sensitive data in "public" dashboards.

### 20.29 Snowflake / BigQuery public datasets misconfiguration
- Generally requires auth, but tokens leak often.

### 20.30 Hudson (legacy Jenkins fork)
- Same surface as Jenkins.

---

## CATEGORY 21: HEADERS, COOKIES, FINGERPRINTS — ENRICHMENT DATA

These aren't bugs; they're enrichment data the system uses to know what to scan.

### 21.1 Server / framework fingerprint headers
- `Server:` (Apache, nginx, IIS, Caddy, Cloudflare, gunicorn, uvicorn, hypercorn, daphne, etc.)
- `X-Powered-By:` (PHP, ASP.NET, Express, etc.)
- `X-AspNet-Version:`, `X-AspNetMvc-Version:`
- `X-Generator:` (Drupal, Joomla, etc.)
- `X-Drupal-Cache:`, `X-Drupal-Dynamic-Cache:`
- `X-Powered-CMS:` (Bitrix, etc.)
- `X-Magento-*`
- `X-Shopify-*`
- `X-Pingback:` (WordPress)
- `X-Jenkins:`
- `X-Jira-*`, `X-Confluence-*`
- `X-GitHub-*`, `X-GitLab-*`

### 21.2 Cookie name fingerprints
- `PHPSESSID` → PHP
- `JSESSIONID` → Java
- `ASP.NET_SessionId`, `ASPSESSIONID*` → ASP.NET
- `laravel_session`, `XSRF-TOKEN` → Laravel
- `_session_id`, `csrftoken` → Django/Rails
- `connect.sid` → Express
- `wp-settings-*`, `wordpress_*` → WordPress
- `Drupal.toolbar.*` → Drupal

### 21.3 Favicon hashes
- `mmh3.hash(favicon_bytes)` cross-referenced with public favicon database (favicon.ico databases on GitHub).
- One favicon hash often uniquely identifies a product version.

### 21.4 HTML signature
- `<meta name="generator">` tags.
- Specific class names, comment patterns.

### 21.5 Static asset paths
- `/wp-content/`, `/wp-includes/` → WP
- `/sites/all/`, `/sites/default/` → Drupal
- `/media/jui/` → Joomla
- `/skin/frontend/` → Magento
- `/static/dist/` (no info alone, but version hash in URL = pin version)

### 21.6 Robots.txt patterns
- `Disallow: /wp-admin/` → WP
- `Disallow: /administrator/` → Joomla
- `Disallow: /sites/default/files/` → Drupal

### 21.7 TLS fingerprints (JA3, JA4 server-side)
- Uncommon but useful for unusual stacks.

### 21.8 HTTP/2 SETTINGS frame fingerprint
- Some products have unique HTTP/2 settings combinations.

---

## OPERATIONAL NOTES (How the System Should Use This Corpus)

1. **Don't blast every path at every host.** Fingerprint first (CATEGORY 21), then run only relevant checks. Blasting 5,000 paths at every host gets you blocked, generates noise, and produces many false positives (SPA fallbacks return 200 for everything).

2. **Detection vs validation are separate.** Detection finds candidates; validation confirms. Never report unvalidated findings.

3. **Validation must be safe.** SAFE = read-only. Never write, never modify, never DoS. The one allowed write category is sentinel-document submission for RAG poisoning checks (CATEGORY 15.14), with auto-cleanup.

4. **Default-credential attempts are exactly ONE per (product, credential pair).** No iteration. No brute force. One attempt, log result, move on.

5. **Capture evidence on every confirmed finding.** Request, response (full body, redacted in report), screenshot for visual surfaces, validation log, fingerprint that triggered the detection.

6. **De-duplicate by stable key.** `(detection_id, asset, parameter_or_path, payload_class)`. Re-detection on subsequent scans updates `last_seen`, doesn't create new findings.

7. **Cluster across-asset findings with shared root cause.** One library, one IaC misconfig replicated across 50 subdomains = one finding group with 50 instances.

8. **Auto-generate H1/Bugcrowd report drafts** with: title, severity, asset, reproduction steps (curl-able), evidence (screenshots, request/response), impact statement, suggested remediation, references.

9. **Prioritize the queue** by:
   - KEV-listed CVE matches (top)
   - Default credential successes (top)
   - Validated secret leaks (top)
   - Exposed admin panels (high)
   - Exposed config / source files (high)
   - Backup files (medium)
   - Informational misconfigs (low — batch into weekly reports rather than alerting per-finding)

10. **Respect program scope.** Always intersect findings with the program's published scope JSON (HackerOne, Bugcrowd, Intigriti scope feeds). Out-of-scope findings get silently dropped, not alerted.

11. **Politeness controls.** Per-target rate limit (start at 10 req/s, back off on 429 / WAF challenge). Per-ASN rate limit. Concurrent connection cap.

12. **Maintain per-program "what's been found" state** so re-scans don't re-alert already-submitted findings.

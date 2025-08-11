DSE Linux Deployment SOP — Voilà (Path to Production)
Version: 1.0
Owner: DSE Team
Scope: Deploying Python/Notebook apps as Voilà services on Linux servers (lower envs → Prod). Streamlit/Dash SOPs will reuse this template with changes in the Application Runtime and Reverse Proxy sections.
________________________________________
1) Purpose & Outcomes
This SOP standardizes how we package, secure, deploy, monitor, and operate Voilà applications in Linux environments. It ensures NFRs (security, reliability, observability, performance) are met and that deployments are repeatable and auditable.
Outcomes
•	Idempotent deployments using a fixed directory layout and systemd service.
•	Secure configuration (no hardcoded secrets; TLS, auth options, dependency controls).
•	Health checks, logs, and restart policies.
•	Rollback plan and audit trail.
________________________________________
2) Roles & Responsibilities
•	App Owner (AO): Owns notebook code, requirements, and functional testing.
•	DSE Platform (DSE): Provides base images, vetted packages, standards, and CI/CD patterns.
•	Infra/Operations (Ops): Provision servers, certificates, firewalls; enables monitoring and backups.
•	InfoSec (IS): Reviews TSC compliance, authN/authZ patterns, and data handling.
Approval gates: AO → DSE → IS (as needed) → Ops (release).
________________________________________
3) Environment & Directory Layout
All deployments use /opt/voila_reverse_proxy (configurable). Example tree:
voila_reverse_proxy/
├── config/
│   └── voila.cfg                  # Central config (ports, paths, security)
├── logs/                          # Rotated logs (app, proxy, supervisor)
├── notebooks/                     # Voilà notebooks (read-only in Prod)
│   └── sample_dashboard.ipynb
├── scripts/
│   ├── check_proxy.sh             # Health checks (HTTP)
│   ├── check_voila.sh             # Health checks (HTTP)
│   └── voila_start.sh             # Bootstrap/supervisor entrypoint
├── src/
│   ├── __init__.py
│   ├── config_loader.py           # Config loader
│   ├── logger.py                  # TimedRotating logs
│   ├── voila_launcher.py          # Starts Voilà runtime
│   ├── reverse_proxy.py           # Flask-based HTTP reverse proxy
│   ├── proxy_monitor.py           # Proxy process + health
│   ├── voila_monitor.py           # Voilà health
│   └── main.py                    # Supervisor (restart/backoff)
└── requirements.txt               # Pinned deps (hashes optional)
Ownership/Permissions
•	Create a service user voila; own /opt/voila_reverse_proxy and subfolders.
•	chmod 750 for folders; chmod 640 for config; notebooks read-only in Prod.
________________________________________
4) Prerequisites & Controls
1.	Linux: RHEL 8+/Ubuntu 22.04+. NTP enabled; locale UTF-8.
2.	Python: 3.10+ via system Python or venv; no root-level pip installs.
3.	Network: Open inbound proxy_http_port (and proxy_ws_port if used) via firewall; outbound to internal PyPI/Artifactory.
4.	Certificates/TLS: Either terminate TLS at upstream gateway or run local TLS on proxy (Ops-issued certs in /etc/pki/tls/...).
5.	Secrets: Managed by Vault/KMS/Secret Manager; never stored in voila.cfg or notebooks. Runtime reads tokens via env vars or sidecar.
6.	Dependencies: Only TSC-approved libraries; pin versions in requirements.txt. Optional: use hash-checking mode (pip --require-hashes).
7.	Artifact Source: Code comes from main branch tagged release; supply SBOM (pipdeptree or cyclonedx) in change record.
________________________________________
5) Configuration Standards
config/voila.cfg (single source of truth):
[server]
host = 0.0.0.0
voila_port = 8866
proxy_http_port = 8080
notebook = notebooks/sample_dashboard.ipynb

[security]
auth_enabled = false            ; true when OIDC/Basic is enabled
basic_user =                    ; only for lower env smoke tests
basic_pass =
allowed_origins = *             ; restrict in Prod

[paths]
log_dir = logs
python = /usr/bin/python3
venv = /opt/voila_env           ; optional venv; leave blank to use system python

[process]
pid_dir = /tmp/voila_stack
restart_backoff_seconds = 5
max_restarts = 10
Config rules
•	No secrets in voila.cfg.
•	Ports must be unique per host.
•	Update notebook path on each release if the entry notebook changes.
________________________________________
6) Build & Package
Lower envs:
1.	Create/refresh venv: python3 -m venv /opt/voila_env (owned by voila).
2.	Activate and install: pip install --upgrade pip then pip install -r requirements.txt (from internal index).
3.	Validate import of all kernels/extensions used by notebooks.
Prod artifact:
•	Deliver a tarball (voila_release_<version>.tar.gz) containing config/, notebooks/, src/, scripts/, requirements.txt, and a RELEASE_NOTES.md.
•	Include SBOM and checksum. Ops untars to /opt/voila_reverse_proxy under voila user.
________________________________________
7) Deployment Steps (Idempotent)
1.	Pre-checks (Ops)
o	id voila exists; directory ownership set to voila:voila.
o	Firewall rules for proxy_http_port (and proxy_ws_port if used).
o	TLS certs in place if terminating locally.
2.	Install/Update (Ops)
o	Stop service if running: systemctl stop voila-stack || true.
o	Extract release tarball to /opt/voila_reverse_proxy.
o	(Optional) Rebuild venv and install requirements.
o	chmod and chown as per Section 3.
3.	Configure (AO/DSE)
o	Update config/voila.cfg for ports/notebook path/origins.
4.	Start (Ops)
o	systemctl daemon-reload
o	systemctl enable --now voila-stack
5.	Post-Start Validation
o	Health: curl -fsS http://127.0.0.1:<proxy_http_port>/health
o	App load: open / via proxy URL; validate widget interactivity.
o	Logs: tail logs/supervisor.log, logs/voila.log, logs/proxy.log.
________________________________________
8) Runtime & Service Management
/etc/systemd/system/voila-stack.service:
[Unit]
Description=Voila + Reverse Proxy Stack
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/voila_reverse_proxy
ExecStart=/opt/voila_reverse_proxy/scripts/voila_start.sh
User=voila
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
Common commands
•	Status: systemctl status voila-stack
•	Logs: journalctl -u voila-stack -e
•	Restart: systemctl restart voila-stack
________________________________________
9) Reverse Proxy & WebSockets
•	The provided proxy (src/reverse_proxy.py) forwards HTTP to Voilà (voila_port).
•	Widgets require WebSocket support; DSE standard is to split ports or terminate WS at the same proxy depending on gateway policy.
•	If corporate gateway handles TLS and WS, expose only proxy_http_port internally and let the gateway do TLS offload + routing.
•	For local TLS: run gunicorn/waitress with certs and confirm WS upgrade headers pass-through.
Headers to preserve: Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Protocol.
________________________________________
10) Security Controls
•	AuthN: Enable OIDC (preferred) or Basic for lower env smoke only. OAuth secrets stored in Vault; injected by env vars at service start.
•	AuthZ: Implement RBAC at proxy layer (group claims → role map) or restrict by network segment.
•	TLS: Enforce HTTPS at the gateway; HTTP disabled externally.
•	CSP: Set Content-Security-Policy to limit sources (self + approved CDNs/internal).
•	Package hygiene: Only TSC-approved libs; quarterly review of versions; pip list --outdated report attached to release notes.
•	Data policy: No PII persists in notebooks; temp files written to ephemeral storage; disable filesystem writes unless required.
________________________________________
11) Observability
•	Logs: Rotated at midnight; 14-day retention. Configure logrotate:
/opt/voila_reverse_proxy/logs/*.log {
  daily
  rotate 14
  compress
  missingok
  copytruncate
}
•	Metrics/Health: /health endpoint (proxy). Optionally export Prometheus metrics via a sidecar.
•	Tracing: Optional OpenTelemetry integration in proxy for request traces.
________________________________________
12) NFR Validation (Pre-Prod Checklist)
•	Performance: Load test expected concurrent users; document 95th percentile latency and CPU/memory headroom (≥30%).
•	Resilience: Kill Voilà process; supervisor restarts within restart_backoff_seconds.
•	Capacity: Validate memory footprint of kernel + notebook; set ulimit if necessary.
•	Security: Static deps scan; authN enabled; TLS verified; CSP present.
•	Observability: Logs present; health endpoint returns 200; alerts wired.
Sign-off requires evidence (screenshots or reports) attached to the change ticket.
________________________________________
13) Rollback Plan
•	Keep previous release tarball (-1) on server.
•	To rollback: systemctl stop voila-stack → restore backup directory → systemctl start voila-stack.
•	Validate health and functionality; update ticket with reason and postmortem link.
________________________________________
14) Incident Runbook
•	App down: systemctl status, check logs/supervisor.log. If flapping, raise severity-2 and pin current notebook commit.
•	High error rate: Check recent release; roll back if caused by code change.
•	Auth failures: Verify IdP reachability and token clock skew (NTP).
•	Widget failures: Confirm WS handshake at proxy/gateway; check headers (see Section 9).
________________________________________
15) Sample Commands (Quick Start)
# one-time (ops)
sudo useradd -r -s /bin/false voila
sudo mkdir -p /opt/voila_reverse_proxy && sudo chown -R voila:voila /opt/voila_reverse_proxy

# as voila user
python3 -m venv /opt/voila_env
source /opt/voila_env/bin/activate
pip install --upgrade pip
pip install -r /opt/voila_reverse_proxy/requirements.txt

# start
sudo systemctl daemon-reload
sudo systemctl enable --now voila-stack

# validate
curl -fsS http://127.0.0.1:8080/health && echo OK
________________________________________
16) Acceptance Criteria (attach to Jira)
________________________________________
17) Appendices
A. Minimal requirements.txt
voila==0.5.7
notebook==7.0.7
jupyterlab==4.0.11
flask==3.0.3
waitress==3.0.0
requests==2.32.3
B. Systemd Unit (copy)
(See Section 8.)
C. Health Check Scripts (copy)
•	scripts/check_voila.sh
•	scripts/check_proxy.sh
D. Change Record Template
•	Release ID, Git tag/commit
•	SBOM + checksums
•	Risk Assessment (functional + security)
•	Rollback tested (date)
•	Approvals (AO, DSE, IS, Ops)
________________________________________
End of Document

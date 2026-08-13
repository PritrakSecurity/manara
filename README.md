<!-- TODO: add asset docs/images/pritrak.svg (project logo, ~160px) -->
<!-- <p align="center"><img src="docs/images/pritrak.svg" width="160" alt="Manara DLP" /></p> -->

<h1 align="center">Manara DLP</h1>

<p align="center"><strong>The Open-Core Data Loss Prevention &amp; DSPM Platform.</strong><br>
<em>Visibility is free. Control is paid.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square" alt="Go 1.24">
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square" alt="React 18">
  <img src="https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square" alt="C++20">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/Open--Core-Community%20Free-brightgreen?style=flat-square" alt="Open-Core: Community free">
  <img src="https://img.shields.io/badge/Agent-Windows-0078D6?style=flat-square" alt="Windows endpoint agent">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#community-vs-enterprise-open-core">Community vs Enterprise</a> ·
  <a href="#contributing--security">Contributing</a>
</p>

Manara DLP is an **open-source, self-hosted data loss prevention (DLP) and Data Security Posture Management (DSPM) platform** — a Windows endpoint agent that classifies and hashes files, a Go backend that ingests inventory and policies, and a React admin console with real-time visibility. **Visibility is free and self-hosted; only advanced remediation and automation are paid.**

<!-- TODO: add asset docs/images/dashboard.png (admin console screenshot) -->

---

## 🧭 Why Manara DLP?

Legacy DLP (Forcepoint, Proofpoint, Digital Guardian) costs $50–150 per endpoint per year, takes months of professional-services deployment, and is closed-source — you cannot audit what your own DLP is doing. Manara DLP is source-available, self-hosted, and enrolls an agent with a single PowerShell command.

| The problem | Manara DLP's answer |
|---|---|
| DLP is expensive and per-endpoint licensed | Open-core: the community tier is free forever, self-hosted |
| Months-long rollout with vendor consultants | One `irm ... \| iex` bootstrap command enrolls an agent |
| Data classification is a black box | The classification engine and rules live in this repo — auditable |
| No DSPM — you don't know where sensitive data sits | DSPM inventory, posture, and compliance dashboards in the same console |
| Vendor lock-in and opaque pricing | MIT-licensed code; only advanced automation (UEBA, EDM, playbooks) is paid |

**What ships in this repo**

- **Endpoint agent (Windows, C++20):** a user-mode Windows service that classifies local files, computes SHA-256 hashes, monitors file/USB/clipboard activity, and streams metadata to the backend. It runs **MONITOR_ONLY** by design — it observes and reports, it never blocks.
- **Go backend:** JWT + bcrypt auth, policy & keyword engines, DSPM inventory, incident and approval workflows, real-time WebSocket event stream, and the agent-artifact manifest endpoint.
- **React admin console:** a 7-pillar navigation (Command Center, Data Posture, Detection, Policy Studio, Compliance, Coverage, Administration) with tier-gated features and a live Event Explorer.
- **One-command agent enrollment:** a PowerShell bootstrap that fetches a signed manifest, verifies the artifact SHA-256, and installs the agent as a Windows service.
- **Data classification engine:** rule-based classification with configurable rules and dictionaries, plus keyword test/import/export tooling.

## ⚡ Quick Start

Target: a running admin console **and** an enrolled endpoint in under five minutes.

> **Prerequisites:** PostgreSQL 15+ (or Docker), Go 1.24+, Node 18+. On Windows, Visual Studio 2022 + CMake 3.20+ are needed to build the agent.

**Step 0 — database.** Any Postgres works; the repo ships a dev profile:

```bash
docker compose -f infra/docker-compose.dev.yml up -d postgres
```

**Step 1 — backend.** Configure the required secrets first. This server **refuses to start** without `AES_ENCRYPTION_KEY` and without `JWT_SECRET` (except in `ENVIRONMENT=development`, where it generates a random one). That fail-fast behavior is intentional — no silently-weak defaults.

```bash
cd backend
cp .env.example .env
# edit .env: set JWT_SECRET, AES_ENCRYPTION_KEY, ADMIN_EMAIL, ADMIN_PASSWORD
go run ./cmd/server
```

`ADMIN_EMAIL`/`ADMIN_PASSWORD` seed the admin account (bcrypt-hashed) on startup. If they are missing, the server logs a warning and login stays locked until an admin exists.

**Step 2 — console.** Open <http://localhost:5173> and sign in with the admin credentials you configured.

```bash
cd frontend
npm install
npm run dev
```

**Step 3 — enroll an agent.** Build the agent artifact once (see [Development Setup](#development-setup)), then on each target Windows machine run, **as Administrator**:

```powershell
irm "http://<YOUR-SERVER-IP>:8080/api/v1/install/bootstrap.ps1?server=http://<YOUR-SERVER-IP>:8080" | iex
```

> ⚠️ Plain HTTP is for lab/testing only. For any real deployment, terminate TLS at a reverse proxy in front of the backend (the console API currently serves HTTP; TLS hardening is on the roadmap).

What that one-liner actually does (readable in `backend/internal/api/install.go` + `backend/internal/api/bootstrap.ps1`):

1. Fetches the manifest from `/api/v1/install/manifest` and picks the x64 artifact.
2. Downloads the zip and **verifies the SHA-256** against the manifest before touching the disk.
3. Installs and starts the `PritrakDLP` Windows service (monitor-only), then writes a hardened config under `C:\ProgramData\PritrakDLP`.

> **Troubleshooting:** if the bootstrap fails with *"Agent artifact manifest is not available"*, the agent zip hasn't been built yet — run `.\tools\build-and-package-agent.ps1` first so `backend/static/artifacts/` contains `PritrakDLP-Agent-1.0.0-x64.zip` and `manifest.json`.

The endpoint enrolls, heartbeats, and appears in your dashboard within about a minute — from that point on, classified-file events stream into the Event Explorer in near real time.

## 🏗 Architecture

```
  ┌────────────────────────────┐
  │    React Admin Console     │   React 18 · Vite · TypeScript · Tailwind · Zustand
  └──────────────┬─────────────┘
                 │  HTTPS · REST + WebSocket · JWT Bearer
  ┌──────────────▼─────────────┐
  │        Go Backend          │   Go 1.24 · REST/WebSocket · gRPC · PostgreSQL
  │  auth · policies · DSPM ·  │
  │  events · incident mgmt ·  │
  │  agent artifact + manifest │
  └──────┬──────────────┬──────┘
         │              │
         │  Postgres    │  HTTPS REST · enrollment, heartbeat, telemetry, bootstrap
         │  (SQL)       │
  ┌──────▼──────────────▼──────┐
  │     C++ Endpoint Agent     │   C++20 · Windows service · WinHTTP
  │  classify · SHA-256 · hash │
  │  monitor · report · cache  │
  └────────────────────────────┘
```

| Component | Tech | Responsibility |
|---|---|---|
| Endpoint Agent | C++20, Windows service, WinHTTP | Classifies local files, computes SHA-256 hashes, monitors file/USB/clipboard activity, sends metadata + telemetry to the backend |
| Backend | Go 1.24, PostgreSQL | Auth (JWT + bcrypt), policies, DSPM inventory, incident/approval workflows, real-time WebSocket events, serves the agent zip + signed manifest |
| Admin Console | React 18, Vite, Tailwind, Zustand | 7-pillar navigation, dashboards, tier-gated features, one-command agent bootstrap |

**The event path, end to end:** the agent POSTs telemetry (`/api/telemetry`, `/api/v1/events/batch`) → the backend classifies, persists, and pushes the event to the WebSocket hub (`/ws/events`) → the console's Event Explorer updates live. The agent heartbeats every 30 seconds so endpoint status stays current.

**The admin console, by pillar** (routes defined in `frontend/src/components/layout/Sidebar.tsx`):

| Pillar | What lives there |
|---|---|
| Command Center | Executive overview, posture & risk scorecard, threat & incident pulse, compliance snapshot |
| Data Posture (DSPM) | Data inventory & asset map, classification labels, data flow & lineage, access/exposure, shadow data, posture findings |
| Detection & Investigation | Incident queue & triage, alert tuning, Event Explorer, UEBA, case management, response playbooks |
| Policy Studio | Policy builder & lifecycle, classifiers & rules, dictionaries/EDM, policy simulation, exceptions, change review |
| Compliance & Audit | Framework mapping (GDPR/HIPAA/PCI), audit evidence, DSAR, retention/residency, attestation |
| Coverage & Integrations | Endpoints & agents, cloud/SaaS, network/email gateways, identity sync, SIEM/SOAR exports, sensor health |
| Administration | Users & RBAC, workspace settings, notifications, API keys, platform audit log, license & usage |

**Security posture** (all verifiable in `backend/`):

- JWT tokens are HS256-signed with `JWT_SECRET`; the server **fails fast at startup** if it is unset outside development.
- Passwords are stored as **bcrypt** hashes (`golang.org/x/crypto/bcrypt`); the admin is seeded from `ADMIN_EMAIL`/`ADMIN_PASSWORD`.
- `AES_ENCRYPTION_KEY` is **mandatory** for encrypting AD bind credentials — no default, no silent fallback.
- Browser CORS is restricted to an **explicit origin allowlist** (`ALLOWED_ORIGINS` / `ALLOWED_WEBSOCKET_ORIGINS`).
- Agent installs verify the artifact **SHA-256** against the served manifest before executing.

## 🆓 Community vs Enterprise (Open-Core)

The community edition is free forever: **visibility and triage**. Enterprise adds **control and automation**. Tier gates live in `frontend/src/config/tiers.ts`.

| Capability | Community | Starter | Enterprise |
|---|---|---|---|
| Command Center dashboards, incident triage, event explorer | ✅ | ✅ | ✅ |
| Endpoint monitoring, sensor health, inventory & asset map | ✅ | ✅ | ✅ |
| Policy builder, users/RBAC, framework mapping (GDPR/HIPAA/PCI) | ✅ | ✅ | ✅ |
| DSPM classification labels, access/exposure, shadow data | | ✅ | ✅ |
| SIEM / SOAR / ticketing exports, cloud & SaaS connectors | | ✅ | ✅ |
| Classifiers & detection rules, exceptions & overrides | | ✅ | ✅ |
| **UEBA** (user & entity risk), **EDM** dictionaries & fingerprinting | | | ✅ |
| **Response playbooks**, automated remediation, case management | | | ✅ |
| Data flow & lineage, policy simulation, change review/versioning | | | ✅ |
| DSAR, retention/residency, attestation & sign-off | | | ✅ |
| API keys & automation, platform audit log | | | ✅ |

> **Honest note:** tier gating is currently enforced **client-side** (routes render an upgrade gate instead of the page). Server-side entitlement/license enforcement is on the [roadmap](#roadmap), as is enforcement of the community 15-endpoint cap.

## 🛠 Development Setup

| Prerequisite | Version | Needed for |
|---|---|---|
| Go | 1.24+ | Backend |
| Node.js | 18+ | Frontend |
| PostgreSQL | 15+ | Backend persistence |
| Visual Studio 2022 (C++ workload) + CMake | 3.20+ | Agent |

**Backend**

```bash
cd backend
go run ./cmd/server        # set DATABASE_URL, JWT_SECRET, AES_ENCRYPTION_KEY, ADMIN_EMAIL, ADMIN_PASSWORD
```

Run the backend test suite (`golang.org/x/crypto/bcrypt`, JWT, classification, and validator tests included):

```bash
go test ./...               # or: make test
```

**Frontend**

```bash
cd frontend
npm install
npm run dev                # http://localhost:5173
npm run lint               # eslint, zero-warning
npm run build              # tsc + vite production build
```

**Agent** (builds the user-mode service only — **no WDK required**)

```powershell
.\tools\build-and-package-agent.ps1
# outputs backend/static/artifacts/PritrakDLP-Agent-1.0.0-x64.zip + manifest.json (gitignored)
```

The agent uses **CMake + FetchContent** for `nlohmann/json` and SQLite — no manual dependency setup.

## 📁 Project Structure

```
.
├── agent/          # C++ endpoint agent (usermode service, kernel drivers, common lib)
├── backend/        # Go backend (cmd/, internal/, migrations/, static/ artifacts)
├── frontend/       # React admin console (src/, public/)
├── infra/          # Docker Compose + Dockerfiles (dev stack)
├── installer/      # Windows installer + WDAC policy / signing material
└── tools/          # build-and-package-agent.ps1, contract validators
```

## 🗺 Roadmap

- [x] Windows endpoint agent — user-mode service, MONITOR_ONLY, one-command bootstrap
- [x] Go backend — auth, policies, DSPM inventory, incidents, approvals, WebSocket events
- [x] Admin console — 7-pillar navigation with open-core tier gating
- [x] Data classification engine + configurable classification rules
- [x] Agent artifact pipeline with SHA-256 manifest verification
- [ ] Server-side tier & entitlement enforcement (incl. 15-endpoint community cap)
- [ ] Linux/macOS endpoint agents
- [ ] SIEM/SOAR/EDM integrations as first-class shipped modules
- [ ] TLS-by-default for the console and bootstrap transport
- [ ] Helm chart / Kubernetes deployment profile

Want something on the list prioritized? Open an issue or start a discussion.

## ⚠️ Limitations

Honest constraints, by design:

- **Windows-only agent today** — Linux/macOS endpoints are on the roadmap.
- **Client-side tier enforcement** — gating is enforced in the console; server-side license enforcement is not shipped yet.
- **Pre-1.0** — APIs and storage may change; the agent runs MONITOR_ONLY (it observes and reports, it does not block).
- **HTTP by default** — the console/agent transport is plain HTTP unless you put TLS in front of it.

## ❓ FAQ

**Does the agent block file transfers?**
No. It ships in **MONITOR_ONLY** mode — it classifies, hashes, and reports. Blocking/enforcement actions are on the roadmap.

**Do I need the Windows Driver Kit (WDK) to build the agent?**
No. The user-mode agent builds with CMake + MSVC (`tools/build-and-package-agent.ps1`). The kernel driver is a separate, optional build.

**What is the community endpoint limit?**
The community tier is intended for up to **15 endpoints**. That cap is not yet enforced server-side — enforcement is on the roadmap alongside server-side tier gating.

**Can I put this behind my own proxy / domain?**
Yes. The console honors `VITE_API_URL`, and the bootstrap one-liner accepts any backend via `?server=http://<host>:<port>` — which is exactly how you'd front it with TLS.

**Is there an official Docker image?**
`infra/` ships a dev Docker Compose stack and Dockerfiles for backend/frontend. Production-grade images and a Helm chart are on the roadmap.

**Where do agent artifacts live?**
`tools/build-and-package-agent.ps1` outputs to `backend/static/artifacts/` (zip + `manifest.json`), which the backend serves and which is gitignored.

## 🤝 Contributing & Security

We welcome contributors. Start by opening an issue or discussion, then follow the (in-progress) contributing guide.

<!-- TODO: add CONTRIBUTING.md (build, test, and PR conventions) -->

**Reporting vulnerabilities:** please **do not open a public GitHub issue for security bugs.** Email the details to **contact@pritrak.com** — see [SECURITY.md](SECURITY.md) for the full disclosure process. The public issue tracker is for feature requests and non-security bugs only.

## 📜 License

MIT — see [LICENSE](LICENSE). Manara DLP © 2026.

---

<p align="center">Built with ❤️ by the Manara DLP team. If Manara DLP is useful to you, a ⭐ genuinely helps the project get discovered.</p>

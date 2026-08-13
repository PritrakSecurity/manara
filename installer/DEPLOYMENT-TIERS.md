# Pritrak DLP — Deployment Tiers & Driver Signing

This document is the source of truth for how Pritrak DLP is deployed and how the
kernel driver (when it ships) is signed, loaded, and governed. It exists so that
maintainers, security teams, and customers make decisions from the same set of
facts.

> **Current status (Phase 1): no kernel driver ships, is installed, or is loaded.
> The agent runs in `MONITOR_ONLY` on every tier until enforcement is authorized.
> Everything below about driver signing describes future capability and is
> intentionally not wired into the Phase 1 installer.**

---

## 1. Deployment Tiers

| Tier            | Audience            | Driver signing                              | Secure Boot              | Enforcement mode |
|-----------------|---------------------|---------------------------------------------|--------------------------|------------------|
| T0 Dev/CI       | Maintainers         | Self-signed                                 | Off + test signing       | `FULL_TESTMODE`  |
| T1 Community    | Homelab, research   | Self-signed, published hash                 | Off + test signing       | `FULL_TESTMODE`  |
| T2 Enterprise self-sign | Organizations | Customer's internal CA + WDAC supplemental policy | On                | `FULL`           |
| T3 Official     | General             | Microsoft attestation                       | On                       | `FULL`           |
| **Current**     | **Everyone, today** | **No driver**                               | **On or off**            | **`MONITOR_ONLY`** |

Notes on the tiers:

- **T0 / T1** rely on test signing (`bcdedit /set testsigning on`). This requires
  Secure Boot to be **off**. These tiers are for engineering and lab validation
  only — a test-signing-enabled machine is trivially modifiable by local
  attackers and must never hold real production data.
- **T2** is the target for enterprise self-signing. The driver is signed by the
  customer's own internal CA, and the machine's WDAC (Windows Defender
  Application Control) policy explicitly allow-lists the driver. Secure Boot
  remains **on**.
- **T3** is the only tier appropriate for broad, unattended distribution. The
  driver goes through Microsoft attestation signing (see §4) and loads on
  Secure Boot with no test-signing or WDAC changes.
- The **Current** row is the only one in effect for this phase. No driver is
  required, no driver is shipped, and no driver-loading path is touched by the
  installer.

---

## 2. How a Kernel Driver Can Load — the Only Three Ways

There are exactly three ways a Windows kernel driver can be accepted for load on
a modern system. Every signing/deployment decision in this repository reduces to
one of these three mechanisms:

1. **Test signing** — `bcdedit /set testsigning on`. The kernel accepts any
   driver carrying an `\*.test` attestation (or, historically, a
   `Signer:\*`/embedded test certificate) signature. Requires Secure Boot OFF.
   Boot configuration is user-controlled, so a domain policy must not rely on
   it.
2. **WDAC allow-listing** — the machine runs a WDAC policy (a signed `.p7b` /
   `.bin` policy file) that includes the driver's certificate or hash in the
   `FileRules` / signer allow-list. Works with Secure Boot ON. This is how an
   organization self-signs a kernel driver without Microsoft.
3. **Microsoft attestation / production signing** — the driver is submitted to
   the Microsoft Partner Center Hardware API, attestation-signed by Microsoft's
   signing service, and published. Works with Secure Boot ON with no local
   policy changes. This is the only option suitable for unattended
   general-purpose distribution.

There is no fourth way on a Secure Boot-enabled, HVCI-capable machine. If the
driver is not test-signed, not WDAC-allow-listed, and not Microsoft-signed, it
will not load.

---

## 3. The Legacy Cross-Certificate Path Is Dead

Historically, a driver signed with an EV code-signing certificate and one of
Microsoft's kernel cross-certificates (e.g. `Microsoft Windows Hardware
Compatibility Publisher` cross-certs issued to commercial CAs) would load with
Secure Boot enabled. **All Microsoft kernel cross-certificates have expired.**
This legacy path is closed:

- New EV certificates cannot obtain a valid Microsoft kernel cross-certificate.
- Even where a cross-certified chain can be replayed, the kernel now enforces
  revocation and the expired roots are not trusted.
- Do not design any part of the installation pipeline around an EV certificate
  "just working" as a kernel signature. EV certificates remain useful for
  Authenticode (user-mode binaries) and as the *backing identity* for a Partner
  Center hardware account (§4), but they do not, by themselves, authorize a
  kernel driver on Secure Boot.

---

## 4. Microsoft Attestation Signing (T3)

Attestation signing is the T3 path. Facts that matter:

- **Attestation signing does NOT require HLK or WHQL testing.** You do not need
  a Hardware Lab Kit run or a WHQL submission to get a driver attestation-signed.
- **It DOES require a Partner Center hardware account**, which must be backed by
  an **EV code-signing certificate** for the org (the EV cert is the identity
  that authorizes the hardware account).
- The flow: submit the driver package (`.cab`, `.inf`, `.sys`, catalog) to the
  Hardware API (`api.partner.microsoft.com`), the signing service verifies
  identity + attestation claims, signs with Microsoft's attestation signature,
  and returns signed artifacts for publishing.
- Attestation signing produces drivers that load with Secure Boot ON and are
  HVCI-compatible **only if the driver source is HVCI-safe** (see §5).

### 4.1 Windows Server Caveat

**Windows Server may require full certification for some scenarios.**
Attestation signing is sufficient for many Server SKUs, but certain
configurations (e.g. Server Core with VBS/HVCI enforced, or specific nested
virtualization scenarios) have stricter requirements. **Verify the target Server
configuration before assuming attestation is sufficient.** Test the exact
target SKU with the exact deployment method before committing to it. This is a
standing open item, not a resolved one.

---

## 5. Standing Requirement: HVCI Compatibility

**The driver must be HVCI-compatible for both T2 and T3.**

HVCI (Hypervisor-enforced Code Integrity, aka Memory Integrity) runs kernel
code under VBS and rejects drivers that make prohibited calls (e.g. direct
executable memory allocation with W+X, or calls into `ndis.sys` / `dump_*.sys`
data sections). Consequences:

- An HVCI-incompatible driver will not load on T2 or T3 machines that have
  Memory Integrity enabled (which is the default posture for enterprise +
  Microsoft 365 baseline).
- HVCI compatibility is a **source-level** property. From the start, the driver
  must:
  - Not allocate executable pages via `ExAllocatePool*` with
    `POOL_NX_OPTIN` bypasses — allocate NX by default and mark executable only
    through supported APIs (e.g. `MmProtectMdlSystemAddress`), or avoid
    executable allocations entirely.
  - Not write to kernel text/data sections of other modules.
  - Link only against approved, HVCI-compatible libraries.
  - Run under `MsmVbs`-safe IRQL disciplines (no prohibited MDL manipulation).
- CI must reject a build that breaks HVCI compatibility (analyzers: `CodeQL`
  HVCI rules, WDK's `/kernel /HVCICheck`-style warnings where available, and
  periodic `Device Guard`/`VBS` validation on a test VM).

This requirement applies to any kernel code we ever ship, independent of tier.

---

## 6. Enforcement Mode vs. Tier — The Honest Matrix

A tier describes *how a driver could be loaded*. Enforcement mode describes
*what the agent is allowed to do* and is governed by the Phase 1 state machine:

| Mode                  | Meaning                                                                 | Reachable in Phase 1? |
|-----------------------|-------------------------------------------------------------------------|------------------------|
| `MONITOR_ONLY`        | Observe, classify, report. Nothing is blocked.                          | Yes — the default.     |
| `USERMODE_ENFORCE`    | User-mode enforcement allowed (requires compile + config + policy gate).| Built, gated, NO.      |
| `FULL`                | Kernel enforcement allowed (requires kernel driver).                    | Out of scope.          |
| `FULL_TESTMODE`       | `FULL` under test-signing tiers T0/T1.                                  | Out of scope.          |

The agent reports its **actual** mode and per-provider availability in every
heartbeat. A console that shows `MONITOR_ONLY` is reporting truth, not a bug.

---

## 7. Phase 1 Relationship to This Document

Phase 1 ships no driver. The `installer/signing/*` and `installer/wdac/*`
scripts are **documentation and dry-run tooling** for the driver program that
starts in a later phase:

- `signing/dev-selfsign.ps1`   — T0/T1 local signing + test-signing enablement.
- `signing/enable-testsigning.ps1` — flips the boot flag with a clear warning.
- `signing/verify-signature.ps1` — `signtool verify` + chain/root checks.
- `signing/build-driver-cab.ps1` — package a driver into a submission `.cab`.
- `wdac/sign-driver-internal.ps1` — T2 internal-CA signing + optional WDAC allow-list merge.
- `wdac/generate-wdac-policy.ps1` — generate an HVCI-capable supplemental WDAC policy from templates.
- `wdac/PritrakDLP-Supplemental-template.xml` — the allow-list template consumed by the generator.

None of these are invoked by the Phase 1 bootstrap script. They exist so the
driver pipeline is specified, exercised, and reviewable before enforcement code
exists. Do not wire them into the installer in this phase.

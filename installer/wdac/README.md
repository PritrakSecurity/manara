# Pritrak DLP — WDAC / Enterprise Self-Signing (T2)

T2 lets an organization ship the Pritrak DLP kernel driver signed by the
customer's **own internal CA** while keeping Secure Boot **ON**. That is only
possible because the machine is governed by a **WDAC (Windows Defender
Application Control)** policy that explicitly allow-lists the driver's signer.

> **Phase 1 status:** This directory is a documentation deliverable. The
> scripts are functional and can be used to prepare the T2 pipeline, but they
> are **not wired into the Phase 1 installer** — the Phase 1 agent requires no
> driver and no WDAC changes.

## Prerequisites

- **Windows 10 1809+ / Windows 11 / Server 2019+** with the WDAC tooling
  (`ConvertTo-CIPolicy`, `Set-CIPolicyIdInfo`, `New-CIPolicy`).
- **Windows SDK** for `signtool.exe`.
- An **internal CA** certificate (or a `certutil -csp`-compatible key) with
  code-signing EKU.
- **Administrator rights** on the target machine.
- The target machines must already run a **base WDAC policy**; this directory
  ships a *supplemental* policy that extends it. Do not replace the base policy.

## The two-step pipeline

1. **Sign** the driver with the internal CA:

   ```powershell
   .\sign-driver-internal.ps1 -DriverPath .\PritrakDLP.sys -CertThumbprint <tp> -TimestampUrl http://timestamp.digicert.com
   ```

2. **Generate / refresh** the supplemental policy that allow-lists that signer,
   then compile and deploy it:

   ```powershell
   .\generate-wdac-policy.ps1 -CertThumbprint <tp> -OutputPath .\out\PritrakDLP-Supplemental.xml -BasePolicyId <base-guid>
   # compile to binary policy for deployment
   ConvertTo-CIPolicy -XmlFilePath .\out\PritrakDLP-Supplemental.xml -BinaryFilePath .\out\PritrakDLP-Supplemental.p7b
   # deploy (see https://aka.ms/wdac docs)
   ```

The allow-list must list the **root** certificate of the internal CA (or the
leaf driver-signing certificate), never a hash, so that future driver versions
signed by the same CA keep working without a policy refresh.

## Files

| File                              | Purpose                                                              |
|-----------------------------------|----------------------------------------------------------------------|
| `sign-driver-internal.ps1`        | T2 driver signing with the internal CA (+ optional catalog handling). |
| `generate-wdac-policy.ps1`        | Build a supplemental WDAC policy XML from the template + a signer cert. |
| `PritrakDLP-Supplemental-template.xml` | The allow-list template (GUID + thumbprint placeholders).         |

## Rules you must follow

- **Never deploy a supplemental policy without a base policy.** A supplemental
  policy with no base is rejected at boot.
- **HVCI compatibility is mandatory** (see `../DEPLOYMENT-TIERS.md` §5). A WDAC
  policy cannot make an HVCI-incompatible driver load under Memory Integrity.
- The supplemental policy must include `Enabled:UnsignedSystemIntegrityPolicy`
  and the kernel-mode signing scenario (`131`) exactly as in the template.
- Test in a VM that mirrors the target (Secure Boot ON, HVCI ON) before any
  broad rollout. A bad WDAC policy can lock the machine's boot path; always
  ship a signed rollback policy first.

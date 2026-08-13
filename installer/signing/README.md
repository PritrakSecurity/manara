# Pritrak DLP — Driver Signing Tooling (T0/T1 Dev Signing)

These scripts cover the **development and community** signing tiers (T0/T1) and
provide the low-level primitives the WDAC pipeline (`../wdac`) builds on.

> **Phase 1 status:** These scripts are documentation deliverables. They are
> functional and can be run to prepare a lab machine, but **none of them are
> invoked by the Phase 1 installer** and none of them install, load, or sign a
> driver as part of agent installation. The Phase 1 agent requires no driver.

## Scripts

| Script                       | Purpose                                                                 |
|------------------------------|-------------------------------------------------------------------------|
| `dev-selfsign.ps1`           | Create a self-signed code-signing cert, trust it in the machine stores, and sign one or more binaries. |
| `enable-testsigning.ps1`     | Enable/disable test signing (`bcdedit /set testsigning`) with Secure Boot checks and a forced reboot prompt. |
| `verify-signature.ps1`       | `signtool verify` with optional chain, root-trust, and expected-signer checks. |
| `build-driver-cab.ps1`       | Package a driver's `sys`/`inf`/catalog/`txt` into a `.cab` for submission. |

## Prerequisites

- **Windows SDK** (for `signtool.exe` and `makecab.exe`). Detected under
  `%ProgramFiles(x86)%\Windows Kits\10\bin`.
- **Administrator rights** for any script that touches the certificate stores
  or the boot configuration.
- **T0/T1 only:** Secure Boot **OFF** (required for test signing). The scripts
  check this and refuse where appropriate.

## T0 Dev Loop (per machine)

```powershell
# 1. Enable test signing (reboots)
.\enable-testsigning.ps1 -Enable

# 2. Create a dev cert and sign the driver
.\dev-selfsign.ps1 -FilePath .\PritrakDLP.sys -CertName "PritrakDLP Dev"

# 3. Confirm the signature is loadable
.\verify-signature.ps1 -FilePath .\PritrakDLP.sys -ExpectedSubject "PritrakDLP Dev"
```

## T1 Community

Same loop, but the certificate and the SHA-256 hash of every shipped driver
must be **published** in the release notes. Test signing is off by default for
users; the `enable-testsigning.ps1` script is the only sanctioned way to flip
it, and it prints the security implications before doing so.

## Security notes

- Test-signing-enabled machines are trivially modifiable by local attackers.
  Never run them against production data.
- Never ship a test-signed driver to production endpoints. T1 is a
  research/homelab tier only.
- The self-signed cert is **not** an Authenticode identity. Do not use it to
  sign user-mode release binaries that must be recognised by SmartScreen.

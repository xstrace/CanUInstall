# CanUInstall

CanUInstall is a local-first macOS software admission checker. It inspects public
macOS software packages and produces an explainable report for an IT approver.

The first version supports:

- Local `.app`, `.dmg`, `.pkg`, and `.zip` inputs
- SHA-256 and basic file metadata
- Apple code-signing, notarization, Gatekeeper, entitlements, and privacy usage
  description checks
- Package script and persistence/system-impact checks
- Mach-O architecture, hardened-runtime, and suspicious API/string checks
- Sensitive-data API, data transmission, local storage/encryption, telemetry SDK,
  Apple Privacy Manifest, and App Transport Security checks
- Third-party Framework, dynamic library, bundled runtime, updater, and dependency
  manifest inventory
- Source and publisher identity checks
- Optional VirusTotal hash-only lookup with multi-engine results and sample-history maturity; submitted files are never uploaded
- A 26-control assessment matrix across six dimensions that distinguishes pass,
  informational observations, manual review, risk, insufficient evidence, and not run
- Actionable review instructions that state what to verify and what qualifies for approval
- A local lightweight dynamic-validation plan using built-in macOS process, file,
  network, and unified-log observation tools
- A risk score, confidence level, recommendation, and evidence for every finding
- A live assessment console with upload progress, analysis phases, commands,
  exit codes, elapsed time, summarized output, and copyable logs

It never launches the submitted application or runs package scripts.

## Live progress

Analysis runs as a background job. The browser first displays real upload
progress, then polls incremental events from the local service. Commands are
logged before execution, so a long-running `hdiutil`, `codesign`, or external
reputation request remains visible while it is running. Command output is
truncated to keep the browser responsive.

## Requirements

- macOS
- Python 3.11 or newer
- No Python packages are required

## Run

```bash
python3 app.py
```

Open <http://127.0.0.1:8765>.

The **环境与配置** tab reports which native and optional tools are available,
explains the effect of missing tools, and can save or clear a local VirusTotal
API key without echoing it back to the browser.

To enable VirusTotal:

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
python3 app.py
```

The VirusTotal public API is intended for personal/non-commercial use and is
rate limited. Check its current terms before using this tool in an enterprise
workflow. CanUInstall only queries the SHA-256 and never uploads submitted
files to VirusTotal.

## Safety model

Analysis runs in a temporary directory. Disk images are mounted read-only and
detached after inspection. When Tart dynamic observation is enabled, supported
apps are launched only inside a disposable clone of `TART_BASE_VM` (default:
`tahoe-base`) with a read-only sample share and host-only networking. The clone
is stopped and deleted after observation. PKG installers are not automatically
installed because they can require interactive administrator authorization.

This is a decision-support tool, not proof that software is safe. Static
analysis can miss behavior that only appears after launch, login, user
interaction, or a later update. Data-security API and SDK matches indicate
capability or bundled components; they do not prove that data was collected,
uploaded, or leaked.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

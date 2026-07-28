# 🛡️ Mini Sandbox

> **Developed by Karan Dhaodiyal**

<p align="center">
  <a href="https://github.com/karandhaodiyal28-hash/mini-sandbox">
    <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=24&pause=1000&color=00D4AA&center=true&vCenter=true&width=680&height=60&lines=Mini+Sandbox;Open+untrusted+URLs+and+files+safely;Preview+phishing+and+malware+in+isolation;RAM-only%2C+No+VM%2C+No+Docker%2C+100%25+Free" alt="Mini Sandbox — typing banner" />
  </a>
</p>

<p align="left">
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?logo=windows&logoColor=white">
  <img alt=".NET 8" src="https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white">
  <img alt="Language: C#" src="https://img.shields.io/badge/C%23-100%25-239120?logo=csharp&logoColor=white">
  <img alt="UI: WPF" src="https://img.shields.io/badge/UI-WPF%20%2B%20WebView2-2C2C54">
  <img alt="Build" src="https://img.shields.io/badge/build-passing-brightgreen">
  <img alt="Size" src="https://img.shields.io/badge/exe-%3C%2020%20MB-blue">
  <img alt="Cost" src="https://img.shields.io/badge/price-free-success">
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-informational">
</p>

A **free, lightweight, standalone Windows application** that opens untrusted URLs
and files inside an isolated preview environment — protecting you from phishing,
malware, and drive-by exploits **without virtual machines, Docker, or any paid
service.**

- **Target OS:** Windows 10/11 (x64)
- **Author:** Karan Dhaodiyal ([@karandhaodiyal28-hash](https://github.com/karandhaodiyal28-hash))
- **Stack:** C# / .NET 8 · WPF (ModernWPF) · WebView2 · SQLite · Windows DPAPI
- **License:** MIT
- **Footprint:** framework-dependent single-file `.exe`, **well under 20 MB**

> ⚠️ **Security honesty first.** This is a user-mode, unsigned tool. It layers
> several strong, real mitigations (WebView2's own Chromium sandbox, Job Object
> limits, RAM-only content, LOLBin killing, CDR, multi-feed reputation). It is a
> powerful risk-reduction layer, **not** a hypervisor-grade escape-proof VM. See
> [Security Model & Honest Limitations](#-security-model--honest-limitations).

---

## ✨ Features

### Isolation & ephemerality
- WebView2 **InPrivate** renderer with a throw-away profile that is securely wiped.
- **Job Object** limits: per-process memory ceiling, CPU hard-cap, kill-on-close.
- **RAM-only** content pipeline — downloads never touch disk; buffers are
  cryptographically wiped (random overwrite → zero) before release.
- **Popup / new-window** suppression and **download blocking** by default.
- **LOLBin guard** — actively terminates `cmd.exe`, `powershell.exe`, `mshta.exe`,
  `wscript`, `cscript`, `regsvr32`, `rundll32`, `msiexec`, … if a payload spawns
  them under the sandbox process tree.
- **Per-session fingerprint randomization**: User-Agent, language, screen metrics,
  timezone, WebGL vendor/renderer, and canvas-readback noise.

### Content Disarm & Reconstruction (CDR)
- **PDF** — byte-level neutralization of `/JavaScript`, `/OpenAction`, `/AA`,
  `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, … (xref offsets preserved).
- **Office (DOCX/XLSX/PPTX + macro variants)** — strips VBA macros, OLE objects,
  ActiveX and external links; rebuilds visible text as static, script-free HTML.
- **Images** — re-encoded through SkiaSharp to a clean PNG, dropping EXIF/XMP/IPTC
  and any appended payloads, with decompression-bomb dimension validation.

### Multi-layer threat intelligence (all free)
- **VirusTotal v3** with a thread-safe 4/min sliding-window limiter, a SQLite
  500/day quota that auto-resets, and a 24 h local hash/URL cache.
- **OpenPhish** live feed, **Certificate Transparency** (crt.sh), **RDAP** domain
  age, **DNS-over-HTTPS** (Cloudflare → Quad9) with malware-block detection.
- **Have I Been Pwned** password checks using the **k-Anonymity** model (only the
  first 5 SHA-1 characters are sent).
- **Offline heuristics**: magic-byte vs extension, Shannon entropy, suspicious
  string/API extraction, PE header sanity.
- **YARA-lite**: a dependency-free pure-C# engine for community-style rules.
- **Anti-phishing**: IDN/homograph skeletonization + Levenshtein typosquatting.

### UX & data
- Modern dark-mode UI with a live threat dashboard, status badge, session timer,
  network log, and a prominent **Force Destroy Session** button.
- **Encrypted API key** at rest via **Windows DPAPI** (`CurrentUser`), key held in
  a `SecureString`, buffers zeroed after use, DoD-style 3-pass secure delete.
- **Custom blocklists** (domain/IP/hash/regex) + hosts-file import (StevenBlack, …).

---

## 🌐 Online vs Offline mode & limits

**Offline mode** — no API key, no internet needed; always runs, instant:
- **File checks:** magic-byte vs extension mismatch, Shannon entropy, suspicious
  API/string extraction, PE-header sanity, and **YARA-lite** signature rules.
- **URL checks:** IDN/homograph skeletonization + Levenshtein typosquatting and
  your local custom blocklists.
- Full **isolated preview + CDR** always apply, key or not.

**Online mode** — layered on top when a VirusTotal key and/or internet is present:
- VirusTotal v3 (file-hash + URL), OpenPhish, Certificate Transparency (crt.sh),
  RDAP domain age, DNS-over-HTTPS block detection, HIBP (k-anonymity).
- Every network layer is individually **fault-tolerant / fail-safe** — a timeout,
  missing key or exhausted quota never blocks the offline verdict.

**Scoring (identical in both modes):** each layer emits a weighted verdict →
`score = min(100, strongest_malicious_weight + Σ(suspicious_weights)/2)` →
**≥ 70 = Malicious**, **35–69 = Suspicious**, **< 35 = Safe**. If *no* layer could
assess the target at all (every signal was purely informational), the verdict is
reported as **Unknown** rather than a false *Safe*. Every finding is listed with
its source and reason, so you always see *why* something was flagged.

**Limits**

| Item | Value |
|---|---|
| Max file / download size | **100 MB** (hard in-memory cap; larger inputs are rejected) |
| Deep heuristic/entropy scan window | first **1 MB** of the file |
| VirusTotal free tier | 4 requests/min, 500/day (auto rate-limited + cached) |
| Session storage | **RAM only — 0 bytes written to disk** |

---

## 🚀 Getting started

### Prerequisites
| Requirement | Notes |
|---|---|
| Windows 10 (1809+) / 11 x64 | — |
| [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) | Free |
| [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) | Pre-installed on current Win 10/11 |
| .NET 8 **SDK** | Only needed to build from source |

### Build & run
```powershell
git clone <your-repo-url> ZeroTrustSandbox
cd ZeroTrustSandbox
dotnet restore ZeroTrustSandbox.sln
dotnet run --project ZeroTrustSandbox/ZeroTrustSandbox.csproj
```

### Produce the single-file exe (< 20 MB)
```powershell
dotnet publish ZeroTrustSandbox/ZeroTrustSandbox.csproj `
  -c Release -r win-x64 --self-contained false `
  -p:PublishSingleFile=true -o publish
```
The result is `publish/MiniSandbox.exe`. It is framework-dependent, which is
what keeps it small; the .NET 8 Desktop Runtime + WebView2 Runtime provide the
rest (both free and typically already present on Windows 10/11).

### Run the tests
```powershell
dotnet test ZeroTrustSandbox.sln
```

---

## 🔑 Configuration

Open **⚙ Settings → API Keys** and paste a free
[VirusTotal API key](https://www.virustotal.com/gui/join-us) (64 hex chars).
It is validated, then stored **DPAPI-encrypted** at
`%AppData%\ZeroTrustSandbox\user_key.dat`. Everything works without a key — VT
layers simply become "skipped / opened in isolated mode".

All runtime data lives under `%AppData%\ZeroTrustSandbox\`
(`sandbox.db`, `settings.json`, `logs/`, `yara/`, `blocklists/`). Drop extra
`*.yar` rules into the `yara/` folder to extend detection.

---

## 🧭 Architecture

```
ZeroTrustSandbox/
├── App.xaml(.cs)              # DI container, Serilog, global exception handling
├── MainWindow.xaml(.cs)       # Dark UI + IPreviewSurface implementation
├── app.manifest               # asInvoker, per-monitor DPI, UTF-8
├── Common/AppPaths.cs         # all paths via Environment.SpecialFolder
├── Models/                    # ScanResult, ThreatVerdict, SessionInfo, AppSettings
├── ViewModels/                # MVVM base, RelayCommand, Main/Settings VMs
├── Converters/                # brush/level/bool value converters
├── Core/
│   ├── SandboxEngine.cs       # WebView2 session lifecycle & policy
│   ├── ScanOrchestrator.cs    # multi-layer aggregation + scoring
│   ├── ProcessIsolation.cs    # Job Object (memory/CPU/kill-on-close)
│   ├── ProcessIsolation.Notes.md
│   └── MemoryManager.cs       # RAM-only buffers + secure wipe
├── Security/
│   ├── VirusTotalScanner.cs   ThreatIntelligence.cs   HibpClient.cs
│   ├── YaraScanner.cs / YaraRule.cs   HeuristicAnalyzer.cs
│   ├── TyposquatDetector.cs   KeyProtector.cs   SecureDelete.cs
│   └── ClipboardGuard.cs      ProcessGuard.cs
├── CDR/ PdfDisarmer · OfficeDisarmer · ImageDisarmer
├── Network/ UrlResolver · DnsOverHttps · NetworkLogger · FingerprintGenerator
├── Data/ DatabaseContext · CacheManager · SettingsManager · BlocklistManager
├── Services/ SlidingWindowRateLimiter
└── Resources/ YaraRules/*.yar · Blocklists/top-domains.txt
```

**Design principles:** MVVM, constructor DI (`Microsoft.Extensions.DependencyInjection`),
`async/await` for all I/O, Serilog file+console sinks, `IDisposable`/`IAsyncDisposable`
throughout, and .NET analyzers enabled (surfaced as warnings; flip on
`-warnaserror` once your analyzer baseline is clean).

---

## 🔐 Security Model & Honest Limitations

**What genuinely protects you**
1. **WebView2's own Chromium sandbox** already runs renderers in a lowered-token
   AppContainer/Low-integrity process — stronger than anything a managed app can
   bolt on, and always on.
2. **Job Object** memory/CPU caps + kill-on-close, enforced by the OS kernel.
3. **RAM-only** content + secure wipe → nothing sensitive persists to disk.
4. **ProcessGuard** kills living-off-the-land binaries spawned from the tree.
5. **CDR** removes active content before anything is rendered.
6. **Reputation & heuristics** warn (or block) before you ever open a target.

**What this tool is *not*** (be realistic):
- It is **not** a VM/hypervisor. A true kernel/renderer 0-day escape is out of
  scope for any free user-mode tool.
- Managed code **cannot** hook `CreateProcess` kernel-wide; `ProcessGuard` is a
  fast polling monitor, not an inline hook.
- Because WebView2 owns its child processes, we cannot attach a custom restricted
  token / integrity SID to them — we rely on Chromium's sandbox instead
  (see `Core/ProcessIsolation.Notes.md`).
- Secure-delete overwrite cannot guarantee erasure on wear-leveled SSDs; the real
  protection is that data stays in RAM.

For maximum hardening, package as **MSIX with an AppContainer** capability set and
sign the binary (roadmap).

---

## 🔧 Deviations from the original spec (and why)

| Spec item | Shipped instead | Reason |
|---|---|---|
| `YaraSharp` (native libyara) | Pure-C# **YARA-lite** engine | Avoids native DLL bloat & fragile P/Invoke; keeps exe small |
| `PdfiumViewer` (native) | Byte-level **PDF disarmer** | No native pdfium binaries; deterministic neutralization |
| Kernel `CreateProcess` hook | Parent-PID descendant **monitor** | Kernel hooks need a driver; monitor is fully managed |
| Restricted-token renderer launch | Rely on **WebView2's** sandbox | WebView2 owns its child processes |
| Self-contained exe | **Framework-dependent** single-file | Required to stay **< 20 MB** (WPF doesn't trim) |

Everything else (VirusTotal, OpenPhish, crt.sh, RDAP, DoH, HIBP, DPAPI, SQLite,
SkiaSharp, ZIP/OOXML-based Office handling, ModernWPF, Serilog, DI, xUnit) is
implemented as specified.

---

## 🗺️ Roadmap
- MSIX packaging + AppContainer capability set + code signing
- Session report export (PDF/JSON) UI surface
- Optional consented submission to free online sandboxes
- Localization bundles (es/fr/de/zh)

## 🤝 Contributing
Issues and PRs welcome. Please run `dotnet test` and make sure `dotnet build
-c Release` is clean before submitting. Add new detection logic behind the
existing analyzer interfaces and include unit tests.

## 📄 License
[MIT](LICENSE) © 2026 Karan Dhaodiyal.

Third-party services (VirusTotal, OpenPhish, crt.sh, HIBP, Cloudflare/Quad9 DoH,
RDAP) are used under their respective free-tier terms; review those terms before
production use.

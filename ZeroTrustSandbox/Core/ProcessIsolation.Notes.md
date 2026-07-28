# Process Isolation — Design Notes

This document explains the layered isolation model and, importantly, the honest
boundaries of what a **free, unsigned, user-mode** tool can enforce on Windows
10/11 without a driver, a hypervisor, or Docker.

## What is enforced from managed code today

| Control | Mechanism | File |
|---|---|---|
| Memory ceiling (per process) | Job Object `JOB_OBJECT_LIMIT_PROCESS_MEMORY` | `ProcessIsolation.cs` |
| CPU cap (1 core / %) | Job Object CPU-rate hard cap | `ProcessIsolation.cs` |
| Kill whole tree on close | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | `ProcessIsolation.cs` |
| Active-process cap | `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` | `ProcessIsolation.cs` |
| Block LOLBins (cmd/powershell/…) | Parent-PID descendant monitor + `Kill` | `ProcessGuard.cs` |
| RAM-only content | In-memory buffers, secure wipe | `MemoryManager.cs` |
| Ephemeral browser profile | InPrivate WebView2 + wiped profile dir | `SandboxEngine.cs` |
| No disk downloads | `DownloadStarting` cancelled | `SandboxEngine.cs` |
| Popup / new-window block | `NewWindowRequested` handled | `SandboxEngine.cs` |
| Per-request block/allow | `WebResourceRequested` filter | `SandboxEngine.cs` |

## Low Integrity / Restricted Token / AppContainer

The spec asks for launching renderers at **Low Integrity (S-1-16-4096)**, with a
**restricted token** that strips `SeDebugPrivilege`, `SeShutdownPrivilege`,
`SeBackupPrivilege`, `SeRestorePrivilege`, and inside an **AppContainer**.

Reality with WebView2:

* WebView2 spawns and manages its **own** browser + renderer child processes.
  We do not `CreateProcess` them ourselves, so we cannot pass a restricted
  token or an integrity SID at creation time. The Chromium engine already runs
  its renderers in a **sandbox with a lowered token and an AppContainer/Low
  integrity** by default — that is the isolation WebView2 provides out of the
  box, and it is stronger than what we could bolt on from managed code.
* For content **we** launch (none by default), the pattern is:
  1. `CreateRestrictedToken` (disable the listed privileges + add
     `WRITE_RESTRICTED`),
  2. set the token integrity level to Low via `SetTokenInformation`
     (`TokenIntegrityLevel`, SID `S-1-16-4096`),
  3. `CreateProcessAsUser` with `CREATE_SUSPENDED`,
  4. `AssignProcessToJobObject` (see `ProcessIsolation`),
  5. resume.

The Job Object + descendant monitor above is the reliable, always-on layer; the
restricted-token launch path is documented here as the extension point for any
future non-WebView2 renderers.

## Registry / filesystem virtualization

Running the whole app at Low integrity (or as a Windows *AppContainer* package)
causes Windows to **virtualize** registry and filesystem writes automatically.
Because this build ships as a portable, framework-dependent single-file exe, we
rely on: (a) WebView2's own renderer sandbox, (b) the RAM-only content path, and
(c) `ProcessGuard` killing any LOLBin a payload tries to spawn. Packaging as MSIX
with an AppContainer capability set is the recommended hardening step for a
signed release and is noted in the README roadmap.

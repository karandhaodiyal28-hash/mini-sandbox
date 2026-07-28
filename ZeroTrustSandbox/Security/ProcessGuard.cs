using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Watches for dangerous "living-off-the-land" binaries (cmd.exe, powershell,
/// wscript, mshta, cscript, regsvr32, rundll32, msiexec) being spawned as
/// descendants of the sandbox process tree and terminates them immediately.
/// </summary>
/// <remarks>
/// A kernel-level CreateProcess hook would require a driver or Detours-style
/// user-mode hooking that is out of scope for a lightweight, unsigned tool.
/// This polling monitor is a pragmatic, fully-managed mitigation that pairs
/// with the Job Object limits applied in <c>ProcessIsolation</c>.
/// </remarks>
public sealed class ProcessGuard : IDisposable
{
    private static readonly HashSet<string> Blocked = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "mshta.exe",
        "cscript.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
        "conhost.exe", "wmic.exe", "bitsadmin.exe", "certutil.exe"
    };

    private readonly ILogger<ProcessGuard> _log;
    private readonly HashSet<int> _protectedTree = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _monitor;

    public int TerminatedCount { get; private set; }

    public event EventHandler<string>? BlockedProcessKilled;

    public ProcessGuard(ILogger<ProcessGuard> log)
    {
        _log = log;
        _protectedTree.Add(Environment.ProcessId);
    }

    public static bool IsBlocked(string imageName) => Blocked.Contains(imageName);

    /// <summary>Registers a known sandbox descendant PID (e.g. a WebView2 host).</summary>
    public void Track(int pid)
    {
        lock (_protectedTree)
        {
            _protectedTree.Add(pid);
        }
    }

    /// <summary>Starts the background polling monitor.</summary>
    public void Start()
    {
        _monitor ??= Task.Run(() => MonitorLoopAsync(_cts.Token));
    }

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ScanOnce();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogDebug(ex, "ProcessGuard scan iteration failed.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private void ScanOnce()
    {
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var name = proc.ProcessName + ".exe";
                if (!Blocked.Contains(name))
                {
                    continue;
                }

                if (IsSandboxDescendant(proc.Id))
                {
                    proc.Kill(entireProcessTree: true);
                    TerminatedCount++;
                    _log.LogWarning("Blocked and terminated {Name} (pid {Pid}) spawned by sandbox.", name, proc.Id);
                    BlockedProcessKilled?.Invoke(this, name);
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Process exited or access denied; ignore.
            }
            finally
            {
                proc.Dispose();
            }
        }
    }

    private static int GetParentProcessId(IntPtr handle)
    {
        var pbi = new ProcessBasicInformation();
        var status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out _);
        return status == 0 ? pbi.InheritedFromUniqueProcessId.ToInt32() : -1;
    }

    /// <summary>
    /// Walks the parent chain (bounded, cycle-safe) to decide whether
    /// <paramref name="pid"/> descends from the sandbox tree. This catches LOLBins
    /// spawned INDIRECTLY through WebView2 renderer/host processes — not just those
    /// whose direct parent is the app — and requiring an app ancestor also avoids
    /// PID-reuse false positives on unrelated user processes.
    /// </summary>
    private bool IsSandboxDescendant(int pid)
    {
        var visited = new HashSet<int>();
        var current = pid;
        for (var depth = 0; depth < 8; depth++)
        {
            if (!visited.Add(current))
            {
                return false; // cycle / recycled PID
            }

            int parent;
            try
            {
                using var p = Process.GetProcessById(current);
                parent = GetParentProcessId(p.Handle);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                return false; // exited or inaccessible (e.g. protected system process)
            }

            if (parent <= 0)
            {
                return false;
            }
            lock (_protectedTree)
            {
                if (_protectedTree.Contains(parent))
                {
                    return true;
                }
            }
            current = parent;
        }
        return false;
    }

    public void Dispose()
    {
        try
        {
            _cts.Cancel();
            _monitor?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // monitor cancellation
        }
        finally
        {
            _cts.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref ProcessBasicInformation processInformation,
        int processInformationLength,
        out int returnLength);
}

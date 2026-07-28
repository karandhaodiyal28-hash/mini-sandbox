using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace ZeroTrustSandbox.Core;

/// <summary>
/// Wraps a Windows Job Object so that child processes (e.g. the WebView2
/// browser/renderer hosts) are constrained to a memory ceiling, a single CPU
/// core and are force-killed when the job handle closes.
/// </summary>
/// <remarks>
/// Integrity-level lowering (Low/AppContainer) and restricted-token creation
/// are documented in <c>ProcessIsolation.Notes.md</c>; the primary, reliable
/// containment we apply from managed code is the Job Object below, which the
/// OS enforces regardless of what the sandboxed code attempts.
/// </remarks>
public sealed class ProcessIsolation : IDisposable
{
    private readonly ILogger<ProcessIsolation> _log;
    private IntPtr _job = IntPtr.Zero;

    public bool IsActive => _job != IntPtr.Zero;

    public ProcessIsolation(ILogger<ProcessIsolation> log) => _log = log;

    /// <summary>
    /// Creates the job object and applies the limits. Safe to call once per
    /// session. Returns false if the OS refused (limits then simply don't apply).
    /// </summary>
    public bool CreateJob(int maxMemoryMb, int cpuPercent = 100)
    {
        if (IsActive)
        {
            return true;
        }

        _job = CreateJobObject(IntPtr.Zero, null);
        if (_job == IntPtr.Zero)
        {
            _log.LogWarning("CreateJobObject failed (win32 {Err}).", Marshal.GetLastWin32Error());
            return false;
        }

        var extended = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                             | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                             | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                             | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
                ActiveProcessLimit = 8
            },
            ProcessMemoryLimit = (UIntPtr)((ulong)Math.Max(16, maxMemoryMb) * 1024 * 1024)
        };

        if (!SetExtendedLimit(extended))
        {
            _log.LogWarning("SetInformationJobObject(ExtendedLimit) failed (win32 {Err}).", Marshal.GetLastWin32Error());
        }

        ApplyCpuRate(cpuPercent);
        _log.LogInformation("Job object created: {Mb}MB cap, {Cpu}% CPU.", maxMemoryMb, cpuPercent);
        return true;
    }

    /// <summary>Assigns an existing process (by handle) into the job.</summary>
    public bool Assign(IntPtr processHandle)
    {
        if (!IsActive || processHandle == IntPtr.Zero)
        {
            return false;
        }
        var ok = AssignProcessToJobObject(_job, processHandle);
        if (!ok)
        {
            _log.LogWarning("AssignProcessToJobObject failed (win32 {Err}).", Marshal.GetLastWin32Error());
        }
        return ok;
    }

    private bool SetExtendedLimit(JOBOBJECT_EXTENDED_LIMIT_INFORMATION info)
    {
        var length = Marshal.SizeOf(info);
        var ptr = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(info, ptr, false);
            return SetInformationJobObject(_job, JobObjectExtendedLimitInformation, ptr, (uint)length);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    private void ApplyCpuRate(int cpuPercent)
    {
        if (cpuPercent is <= 0 or >= 100)
        {
            return;
        }

        var info = new JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
        {
            ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            CpuRate = (uint)(cpuPercent * 100) // in 1/100 of a percent
        };

        var length = Marshal.SizeOf(info);
        var ptr = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(info, ptr, false);
            SetInformationJobObject(_job, JobObjectCpuRateControlInformation, ptr, (uint)length);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public void Dispose()
    {
        if (_job != IntPtr.Zero)
        {
            // Closing the handle triggers KILL_ON_JOB_CLOSE for every process
            // still assigned to the job.
            CloseHandle(_job);
            _job = IntPtr.Zero;
        }
    }

    // ---- P/Invoke -------------------------------------------------------

    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectCpuRateControlInformation = 15;

    private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    private const uint JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
    private const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    private const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1;
    private const uint JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    {
        public uint ControlFlags;
        public uint CpuRate;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoType, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}

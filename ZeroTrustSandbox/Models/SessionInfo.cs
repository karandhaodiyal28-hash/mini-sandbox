using System.Collections.ObjectModel;

namespace ZeroTrustSandbox.Models;

/// <summary>Represents a single captured HTTP request/response pair.</summary>
public sealed class NetworkLogEntry
{
    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;
    public required string Method { get; init; }
    public required string Uri { get; init; }
    public int StatusCode { get; set; }
    public long BytesReceived { get; set; }
    public string? ResourceType { get; set; }
    public bool Blocked { get; set; }
    public string? BlockReason { get; set; }
}

/// <summary>
/// Live state for one sandbox session. Exposed to the UI so the timer, network
/// log and threat findings update in real time.
/// </summary>
public sealed class SessionInfo
{
    public Guid Id { get; } = Guid.NewGuid();
    public DateTimeOffset StartedUtc { get; } = DateTimeOffset.UtcNow;
    public string? Target { get; set; }
    public TargetKind Kind { get; set; }

    /// <summary>Randomized per-session browser fingerprint.</summary>
    public required BrowserFingerprint Fingerprint { get; init; }

    public ObservableCollection<NetworkLogEntry> Network { get; } = new();
    public ObservableCollection<ThreatVerdict> LiveFindings { get; } = new();

    public int RequestsBlocked { get; set; }
    public long BytesTransferred { get; set; }

    public TimeSpan Elapsed => DateTimeOffset.UtcNow - StartedUtc;
}

/// <summary>Randomized fingerprint injected into the isolated renderer.</summary>
public sealed class BrowserFingerprint
{
    public required string UserAgent { get; init; }
    public required string AcceptLanguage { get; init; }
    public int ScreenWidth { get; init; }
    public int ScreenHeight { get; init; }
    public int ColorDepth { get; init; }
    public required string Timezone { get; init; }
    public required string WebGlVendor { get; init; }
    public required string WebGlRenderer { get; init; }
}

using System.Collections.ObjectModel;

namespace ZeroTrustSandbox.Models;

/// <summary>Overall risk classification used by the UI status badge.</summary>
public enum ThreatLevel
{
    /// <summary>Not yet scanned.</summary>
    Unknown = 0,
    /// <summary>Scanned, no indicators found.</summary>
    Safe = 1,
    /// <summary>Some low-confidence indicators; proceed with caution.</summary>
    Suspicious = 2,
    /// <summary>High-confidence malicious indicators.</summary>
    Malicious = 3
}

/// <summary>The kind of target being previewed.</summary>
public enum TargetKind
{
    Url = 0,
    File = 1
}

/// <summary>
/// Aggregated result of scanning a single target (URL or file) across all
/// enabled intelligence layers.
/// </summary>
public sealed class ScanResult
{
    public string Target { get; init; } = string.Empty;
    public TargetKind Kind { get; init; }
    public string? Sha256 { get; init; }

    public ThreatLevel Level { get; set; } = ThreatLevel.Unknown;

    /// <summary>Aggregate reputation score in the range 0 (safe) - 100 (dangerous).</summary>
    public int RiskScore { get; set; }

    /// <summary>Individual findings contributed by each analyzer.</summary>
    public Collection<ThreatVerdict> Verdicts { get; } = new();

    public DateTimeOffset ScannedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>True when the result was served from the local SQLite cache.</summary>
    public bool FromCache { get; set; }

    public void Add(ThreatVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(verdict);
        Verdicts.Add(verdict);
    }
}

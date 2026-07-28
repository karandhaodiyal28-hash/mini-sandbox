namespace ZeroTrustSandbox.Models;

/// <summary>
/// A single finding produced by one analyzer/intelligence source
/// (e.g. VirusTotal, PhishTank, entropy heuristic, YARA-lite).
/// </summary>
public sealed class ThreatVerdict
{
    /// <summary>Human readable source name, e.g. "VirusTotal".</summary>
    public required string Source { get; init; }

    public ThreatLevel Level { get; init; } = ThreatLevel.Unknown;

    /// <summary>Short description shown in the dashboard.</summary>
    public required string Summary { get; init; }

    /// <summary>Optional detailed evidence (JSON, matched rule name, etc.).</summary>
    public string? Detail { get; init; }

    /// <summary>Confidence weighting (0-100) used when aggregating scores.</summary>
    public int Weight { get; init; } = 50;

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public static ThreatVerdict Safe(string source, string summary) =>
        new() { Source = source, Level = ThreatLevel.Safe, Summary = summary, Weight = 10 };

    public static ThreatVerdict Info(string source, string summary, string? detail = null) =>
        new() { Source = source, Level = ThreatLevel.Unknown, Summary = summary, Detail = detail, Weight = 0 };

    public static ThreatVerdict Warn(string source, string summary, int weight = 40, string? detail = null) =>
        new() { Source = source, Level = ThreatLevel.Suspicious, Summary = summary, Weight = weight, Detail = detail };

    public static ThreatVerdict Danger(string source, string summary, int weight = 90, string? detail = null) =>
        new() { Source = source, Level = ThreatLevel.Malicious, Summary = summary, Weight = weight, Detail = detail };
}

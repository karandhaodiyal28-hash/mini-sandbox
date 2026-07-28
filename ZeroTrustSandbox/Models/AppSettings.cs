namespace ZeroTrustSandbox.Models;

/// <summary>
/// User-configurable application settings. Persisted (minus the API key, which
/// lives DPAPI-encrypted on disk) as JSON via <c>SettingsManager</c>.
/// </summary>
public sealed class AppSettings
{
    // General
    public bool StartInDarkMode { get; set; } = true;
    public string Language { get; set; } = "en";
    public bool HighContrast { get; set; }
    public int SessionTimeoutMinutes { get; set; } = 30;

    // Security toggles
    public bool EnableVirusTotal { get; set; } = true;
    public bool EnablePhishTank { get; set; } = true;
    public bool EnableOpenPhish { get; set; } = true;
    public bool EnableAbuseIpDb { get; set; }
    public bool EnableUrlVoid { get; set; }
    public bool EnableHibp { get; set; } = true;
    public bool EnableCertTransparency { get; set; } = true;
    public bool EnableYaraLite { get; set; } = true;
    public bool EnableHeuristics { get; set; } = true;

    // Network
    public bool EnableDnsOverHttps { get; set; } = true;
    public string DohPrimary { get; set; } = "https://cloudflare-dns.com/dns-query";
    public string DohFallback { get; set; } = "https://dns.quad9.net/dns-query";
    public bool NetworkIsolationMode { get; set; }
    public bool WhitelistMode { get; set; }

    // Isolation
    public int MaxSessionMemoryMb { get; set; } = 50;
    public int MaxDownloadSizeMb { get; set; } = 100;
    public bool RandomizeFingerprint { get; set; } = true;
    public bool BlockThirdPartyCookies { get; set; } = true;

    // Forensics
    public bool RecordNetworkTraffic { get; set; } = true;
    public bool AutoScreenshotOnThreat { get; set; } = true;

    // API usage limits (VirusTotal free tier)
    public int VtRequestsPerMinute { get; set; } = 4;
    public int VtRequestsPerDay { get; set; } = 500;
    public int CacheTtlHours { get; set; } = 24;

    // Key rotation reminder
    public DateTimeOffset? ApiKeySetUtc { get; set; }
    public int KeyRotationDays { get; set; } = 90;

    public AppSettings Clone() => (AppSettings)MemberwiseClone();
}

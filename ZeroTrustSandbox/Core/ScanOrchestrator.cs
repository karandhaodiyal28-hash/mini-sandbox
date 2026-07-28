using Microsoft.Extensions.Logging;
using ZeroTrustSandbox.Data;
using ZeroTrustSandbox.Models;
using ZeroTrustSandbox.Network;
using ZeroTrustSandbox.Security;

namespace ZeroTrustSandbox.Core;

/// <summary>
/// Runs the full multi-layer analysis pipeline for a target and aggregates the
/// individual verdicts into a single <see cref="ScanResult"/> with an overall
/// risk score and threat level.
/// </summary>
public sealed class ScanOrchestrator
{
    private readonly VirusTotalScanner _vt;
    private readonly ThreatIntelligence _intel;
    private readonly TyposquatDetector _typo;
    private readonly UrlHeuristicAnalyzer _urlHeuristics;
    private readonly HeuristicAnalyzer _heuristics;
    private readonly YaraScanner _yara;
    private readonly DnsOverHttps _doh;
    private readonly BlocklistManager _blocklist;
    private readonly CacheManager _cache;
    private readonly SettingsManager _settings;
    private readonly ILogger<ScanOrchestrator> _log;

    public ScanOrchestrator(
        VirusTotalScanner vt,
        ThreatIntelligence intel,
        TyposquatDetector typo,
        UrlHeuristicAnalyzer urlHeuristics,
        HeuristicAnalyzer heuristics,
        YaraScanner yara,
        DnsOverHttps doh,
        BlocklistManager blocklist,
        CacheManager cache,
        SettingsManager settings,
        ILogger<ScanOrchestrator> log)
    {
        _vt = vt;
        _intel = intel;
        _typo = typo;
        _urlHeuristics = urlHeuristics;
        _heuristics = heuristics;
        _yara = yara;
        _doh = doh;
        _blocklist = blocklist;
        _cache = cache;
        _settings = settings;
        _log = log;
    }

    /// <summary>Analyzes a URL across all enabled network + offline layers.</summary>
    public async Task<ScanResult> ScanUrlAsync(string sanitizedUrl, string host, CancellationToken ct = default)
    {
        var cfg = _settings.Current;
        var result = new ScanResult { Target = sanitizedUrl, Kind = TargetKind.Url };

        var cacheKey = $"url:{sanitizedUrl}";
        var cached = await _cache.TryGetAsync(cacheKey, ct).ConfigureAwait(false);
        if (cached is not null)
        {
            return cached;
        }

        // Offline first (instant, always runs).
        foreach (var v in _typo.Analyze(host))
        {
            result.Add(v);
        }
        foreach (var v in _urlHeuristics.Analyze(sanitizedUrl))
        {
            result.Add(v);
        }

        // Network layers in parallel; each is individually fault-tolerant.
        var tasks = new List<Task<ThreatVerdict>>();
        if (cfg.EnableVirusTotal && _vt.HasKey)
        {
            tasks.Add(_vt.ScanUrlAsync(sanitizedUrl, cfg.VtRequestsPerDay, ct));
        }
        if (cfg.EnableOpenPhish)
        {
            tasks.Add(_intel.CheckOpenPhishAsync(sanitizedUrl, ct));
        }
        if (cfg.EnableCertTransparency)
        {
            tasks.Add(_intel.CheckCertTransparencyAsync(host, ct));
        }
        tasks.Add(_intel.CheckDomainAgeAsync(host, ct));

        if (cfg.EnableDnsOverHttps)
        {
            tasks.Add(WrapDohAsync(host, ct));
        }

        foreach (var verdict in await Task.WhenAll(tasks).ConfigureAwait(false))
        {
            result.Add(verdict);
        }

        Aggregate(result);
        await PersistAsync(cacheKey, result, ct).ConfigureAwait(false);
        return result;
    }

    /// <summary>Analyzes in-memory file bytes across offline layers + VT hash lookup.</summary>
    public async Task<ScanResult> ScanFileAsync(EphemeralBuffer buffer, string fileName, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        var cfg = _settings.Current;
        var sha = VirusTotalScanner.Sha256Hex(buffer.Span);
        var result = new ScanResult { Target = fileName, Kind = TargetKind.File, Sha256 = sha };

        var cacheKey = $"file:{sha}";
        var cached = await _cache.TryGetAsync(cacheKey, ct).ConfigureAwait(false);
        if (cached is not null)
        {
            return cached;
        }

        // Offline hash reputation — always runs, no network/key needed. Surface the
        // SHA-256 so the user can see it, and flag it if it is on the local blocklist.
        result.Add(ThreatVerdict.Info("SHA-256", sha));
        if (_blocklist.IsHashBlocked(sha))
        {
            result.Add(ThreatVerdict.Danger("Blocklist",
                "File hash matches a known-bad entry in your local blocklist.", weight: 95, detail: sha));
        }

        if (cfg.EnableHeuristics)
        {
            foreach (var v in _heuristics.Analyze(buffer.Span, fileName))
            {
                result.Add(v);
            }
        }
        if (cfg.EnableYaraLite)
        {
            foreach (var v in _yara.Scan(buffer.Span))
            {
                result.Add(v);
            }
        }
        if (cfg.EnableVirusTotal && _vt.HasKey)
        {
            result.Add(await _vt.ScanFileHashAsync(sha, cfg.VtRequestsPerDay, ct).ConfigureAwait(false));
        }

        Aggregate(result);
        await PersistAsync(cacheKey, result, ct).ConfigureAwait(false);
        return result;
    }

    private async Task<ThreatVerdict> WrapDohAsync(string host, CancellationToken ct)
    {
        var dns = await _doh.ResolveAsync(host, ct).ConfigureAwait(false);
        if (dns.Blocked)
        {
            return ThreatVerdict.Danger("DoH", $"{dns.Resolver} blocked this domain (known malicious).", weight: 85);
        }
        if (dns.Resolver == "none")
        {
            // No resolver reachable (offline / feed down) is NOT a threat signal —
            // skip it instead of manufacturing a fake "suspicious" verdict.
            return ThreatVerdict.Info("DoH", "Secure DNS unreachable; skipped.");
        }
        if (!dns.Resolved)
        {
            return ThreatVerdict.Warn("DoH", "Domain did not resolve (possible NXDOMAIN).", weight: 30);
        }
        return ThreatVerdict.Safe("DoH", $"Resolved via {dns.Resolver} ({dns.Addresses.Count} A record(s)).");
    }

    /// <summary>Computes overall level + 0-100 risk score from all verdicts.</summary>
    public static void Aggregate(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var maxDanger = 0;
        var suspicion = 0;
        var hasSafe = false;

        foreach (var v in result.Verdicts)
        {
            switch (v.Level)
            {
                case ThreatLevel.Malicious:
                    maxDanger = Math.Max(maxDanger, v.Weight);
                    break;
                case ThreatLevel.Suspicious:
                    suspicion += v.Weight;
                    break;
                case ThreatLevel.Safe:
                    hasSafe = true;
                    break;
            }
        }

        // Score: dominated by the strongest malicious signal, plus accumulated
        // suspicion, capped at 100.
        var score = Math.Min(100, maxDanger + suspicion / 2);
        result.RiskScore = score;

        result.Level = score switch
        {
            >= 70 => ThreatLevel.Malicious,
            >= 35 => ThreatLevel.Suspicious,
            // Only call it "Safe" when something genuinely assessed the target
            // (a real safe signal, or accumulated-but-low suspicion). If every
            // layer merely skipped (Info only), report Unknown, not a false Safe.
            _ => hasSafe || suspicion > 0 ? ThreatLevel.Safe : ThreatLevel.Unknown
        };
    }

    private async Task PersistAsync(string cacheKey, ScanResult result, CancellationToken ct)
    {
        try
        {
            await _cache.StoreAsync(cacheKey, result, _settings.Current.CacheTtlHours, ct).ConfigureAwait(false);
            await _cache.IncrementStatAsync("files_scanned", 1, ct).ConfigureAwait(false);
            if (result.Level == ThreatLevel.Malicious)
            {
                await _cache.IncrementStatAsync("threats_blocked", 1, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Failed to persist scan result.");
        }
    }
}

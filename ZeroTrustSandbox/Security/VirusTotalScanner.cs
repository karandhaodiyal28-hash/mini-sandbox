using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ZeroTrustSandbox.Data;
using ZeroTrustSandbox.Models;
using ZeroTrustSandbox.Services;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// VirusTotal API v3 client with a sliding-window rate limiter (4/min), a
/// SQLite-tracked daily quota (500/day) and a local SHA-256/URL cache. All
/// failures degrade gracefully to an "open in isolated mode with warning"
/// verdict rather than throwing.
/// </summary>
public sealed class VirusTotalScanner
{
    private const string Src = "VirusTotal";
    private const string Base = "https://www.virustotal.com/api/v3";

    private readonly HttpClient _http;
    private readonly KeyProtector _keys;
    private readonly CacheManager _cache;
    private readonly SlidingWindowRateLimiter _limiter;
    private readonly ILogger<VirusTotalScanner> _log;

    public VirusTotalScanner(
        HttpClient http,
        KeyProtector keys,
        CacheManager cache,
        SlidingWindowRateLimiter limiter,
        ILogger<VirusTotalScanner> log)
    {
        _http = http;
        _keys = keys;
        _cache = cache;
        _limiter = limiter;
        _log = log;
    }

    public bool HasKey => _keys.HasKey;

    /// <summary>Looks up a URL's reputation. Returns an informational verdict on any failure.</summary>
    public async Task<ThreatVerdict> ScanUrlAsync(string url, int dailyLimit, CancellationToken ct = default)
    {
        var urlId = Base64UrlNoPad(url);
        return await QueryAsync($"{Base}/urls/{urlId}", $"vt:url:{url}", dailyLimit, ct).ConfigureAwait(false);
    }

    /// <summary>Looks up a file by SHA-256. Returns an informational verdict on any failure.</summary>
    public async Task<ThreatVerdict> ScanFileHashAsync(string sha256, int dailyLimit, CancellationToken ct = default)
    {
        return await QueryAsync($"{Base}/files/{sha256}", $"vt:file:{sha256}", dailyLimit, ct).ConfigureAwait(false);
    }

    private async Task<ThreatVerdict> QueryAsync(string endpoint, string cacheKey, int dailyLimit, CancellationToken ct)
    {
        if (!_keys.HasKey)
        {
            return ThreatVerdict.Info(Src, "No API key configured; skipped.");
        }

        var cached = await _cache.TryGetAsync(cacheKey, ct).ConfigureAwait(false);
        if (cached is not null && cached.Verdicts.Count > 0)
        {
            var first = cached.Verdicts[0];
            return ThreatVerdict.Info(Src, $"(cache) {first.Summary}", first.Detail);
        }

        if (!await _cache.TryConsumeDailyQuotaAsync(dailyLimit, ct).ConfigureAwait(false))
        {
            _log.LogWarning("VirusTotal daily quota exhausted; opening in isolated mode.");
            return ThreatVerdict.Warn(Src, "Daily quota reached — opened in isolated mode without VT verdict.", weight: 20);
        }

        try
        {
            await _limiter.WaitAsync(ct).ConfigureAwait(false);

            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            var secure = _keys.LoadKeySecure();
            if (secure is null)
            {
                return ThreatVerdict.Info(Src, "API key could not be decrypted; skipped.");
            }
            using (secure)
            {
                secure.Use(key =>
                {
                    request.Headers.TryAddWithoutValidation("x-apikey", key);
                    return true;
                });
            }

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return ThreatVerdict.Info(Src, "Not previously seen by VirusTotal.");
            }
            if (response.StatusCode == (HttpStatusCode)429)
            {
                return ThreatVerdict.Warn(Src, "Rate limited (429) — opened in isolated mode.", weight: 20);
            }
            if (!response.IsSuccessStatusCode)
            {
                return ThreatVerdict.Info(Src, $"VT returned {(int)response.StatusCode}; skipped.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            return Interpret(doc, cacheKey);
        }
        catch (TaskCanceledException)
        {
            return ThreatVerdict.Warn(Src, "Request timed out — opened in isolated mode.", weight: 20);
        }
        catch (HttpRequestException ex)
        {
            _log.LogWarning(ex, "VirusTotal request failed.");
            return ThreatVerdict.Warn(Src, "Network error — opened in isolated mode.", weight: 15);
        }
        catch (JsonException)
        {
            return ThreatVerdict.Info(Src, "Malformed VT response; skipped.");
        }
    }

    private ThreatVerdict Interpret(JsonDocument doc, string cacheKey)
    {
        if (!doc.RootElement.TryGetProperty("data", out var data) ||
            !data.TryGetProperty("attributes", out var attr) ||
            !attr.TryGetProperty("last_analysis_stats", out var stats))
        {
            return ThreatVerdict.Info(Src, "No analysis stats available.");
        }

        var malicious = GetInt(stats, "malicious");
        var suspicious = GetInt(stats, "suspicious");
        var harmless = GetInt(stats, "harmless");
        var undetected = GetInt(stats, "undetected");
        var detail = $"malicious={malicious}, suspicious={suspicious}, harmless={harmless}, undetected={undetected}";

        ThreatVerdict verdict;
        if (malicious >= 3)
        {
            verdict = ThreatVerdict.Danger(Src, $"{malicious} engines flag this as malicious.", weight: 95, detail: detail);
        }
        else if (malicious >= 1 || suspicious >= 3)
        {
            verdict = ThreatVerdict.Warn(Src, $"{malicious} malicious / {suspicious} suspicious detections.", weight: 60, detail: detail);
        }
        else
        {
            verdict = ThreatVerdict.Safe(Src, $"Clean across {harmless + undetected} engines.");
        }

        // Cache a lightweight result so we don't re-spend quota within the TTL.
        var result = new ScanResult { Target = cacheKey, Kind = TargetKind.Url, Level = verdict.Level, RiskScore = verdict.Weight };
        result.Add(verdict);
        _ = _cache.StoreAsync(cacheKey, result, ttlHours: 24, CancellationToken.None);
        return verdict;
    }

    private static int GetInt(JsonElement element, string name)
        => element.TryGetProperty(name, out var v) && v.TryGetInt32(out var i) ? i : 0;

    /// <summary>VirusTotal URL identifier: unpadded base64url of the raw URL.</summary>
    public static string Base64UrlNoPad(string url)
    {
        var bytes = Encoding.UTF8.GetBytes(url);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Computes the SHA-256 of a buffer as a lowercase hex string.</summary>
    public static string Sha256Hex(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

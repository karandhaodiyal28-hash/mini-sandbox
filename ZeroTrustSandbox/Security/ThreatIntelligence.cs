using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Aggregates several free threat-intelligence feeds. Every method is
/// self-contained, has a timeout and never throws to the caller — on failure
/// it returns an informational verdict so a single dead feed can't block a scan.
/// </summary>
public sealed class ThreatIntelligence
{
    private const string Src = "ThreatIntel";
    private readonly HttpClient _http;
    private readonly ILogger<ThreatIntelligence> _log;

    // In-memory OpenPhish feed cache (refreshed hourly).
    private HashSet<string> _openPhish = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _openPhishRefreshed = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _feedGate = new(1, 1);

    public ThreatIntelligence(HttpClient http, ILogger<ThreatIntelligence> log)
    {
        _http = http;
        _log = log;
    }

    /// <summary>Checks a full URL against the cached OpenPhish feed.</summary>
    public async Task<ThreatVerdict> CheckOpenPhishAsync(string url, CancellationToken ct = default)
    {
        try
        {
            await EnsureOpenPhishAsync(ct).ConfigureAwait(false);
            if (_openPhish.Contains(url.TrimEnd('/')))
            {
                return ThreatVerdict.Danger("OpenPhish", "URL present in OpenPhish live phishing feed.", weight: 95);
            }
            return ThreatVerdict.Safe("OpenPhish", "Not listed in OpenPhish feed.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return ThreatVerdict.Info("OpenPhish", "Feed unavailable; skipped.");
        }
    }

    private async Task EnsureOpenPhishAsync(CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow - _openPhishRefreshed < TimeSpan.FromHours(1) && _openPhish.Count > 0)
        {
            return;
        }

        await _feedGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (DateTimeOffset.UtcNow - _openPhishRefreshed < TimeSpan.FromHours(1) && _openPhish.Count > 0)
            {
                return;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            var text = await _http.GetStringAsync("https://openphish.com/feed.txt", cts.Token).ConfigureAwait(false);
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                set.Add(line.TrimEnd('/'));
            }
            _openPhish = set;
            _openPhishRefreshed = DateTimeOffset.UtcNow;
            _log.LogInformation("OpenPhish feed refreshed: {Count} entries.", set.Count);
        }
        finally
        {
            _feedGate.Release();
        }
    }

    /// <summary>Estimates domain age via the free RDAP protocol (rdap.org).</summary>
    public async Task<ThreatVerdict> CheckDomainAgeAsync(string host, CancellationToken ct = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));
            await using var stream = await _http.GetStreamAsync($"https://rdap.org/domain/{Uri.EscapeDataString(host)}", cts.Token).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token).ConfigureAwait(false);

            if (!doc.RootElement.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
            {
                return ThreatVerdict.Info("RDAP", "Registration date unavailable.");
            }

            foreach (var ev in events.EnumerateArray())
            {
                if (ev.TryGetProperty("eventAction", out var action) &&
                    action.GetString() == "registration" &&
                    ev.TryGetProperty("eventDate", out var date) &&
                    DateTimeOffset.TryParse(date.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var reg))
                {
                    var ageDays = (DateTimeOffset.UtcNow - reg).TotalDays;
                    if (ageDays < 30)
                    {
                        return ThreatVerdict.Warn("RDAP", $"Domain registered {ageDays:F0} days ago (very new).", weight: 60,
                            detail: reg.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
                    }
                    if (ageDays < 180)
                    {
                        return ThreatVerdict.Warn("RDAP", $"Domain is {ageDays:F0} days old (relatively new).", weight: 35);
                    }
                    return ThreatVerdict.Safe("RDAP", $"Domain age {ageDays / 365:F1} years.");
                }
            }
            return ThreatVerdict.Info("RDAP", "No registration event found.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return ThreatVerdict.Info("RDAP", "WHOIS/RDAP lookup unavailable; skipped.");
        }
    }

    /// <summary>Queries Certificate Transparency logs (crt.sh) for issued certs.</summary>
    public async Task<ThreatVerdict> CheckCertTransparencyAsync(string host, CancellationToken ct = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            var url = $"https://crt.sh/?q={Uri.EscapeDataString(host)}&output=json";
            await using var stream = await _http.GetStreamAsync(url, cts.Token).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token).ConfigureAwait(false);

            var count = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.GetArrayLength() : 0;
            if (count == 0)
            {
                // crt.sh is heavily rate-limited; an empty result is unreliable as a
                // threat signal (often just a throttled response), so keep it informational.
                return ThreatVerdict.Info("crt.sh", "No CT records returned (new site or rate-limited).");
            }
            return ThreatVerdict.Safe("crt.sh", $"{count} certificate(s) in CT logs.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return ThreatVerdict.Info("crt.sh", "CT log lookup unavailable; skipped.");
        }
    }
}

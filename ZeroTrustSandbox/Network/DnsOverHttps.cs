using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace ZeroTrustSandbox.Network;

/// <summary>
/// DNS-over-HTTPS resolver using the JSON API. Primary is Cloudflare's malware-
/// blocking resolver; on failure it falls back to Quad9. A NXDOMAIN/blocked
/// answer from these resolvers is itself a useful malware signal.
/// </summary>
public sealed class DnsOverHttps
{
    private readonly HttpClient _http;
    private readonly ILogger<DnsOverHttps> _log;
    private readonly string _primary;
    private readonly string _fallback;

    public DnsOverHttps(HttpClient http, ILogger<DnsOverHttps> log,
        string? primary = null, string? fallback = null)
    {
        _http = http;
        _log = log;
        _primary = primary ?? "https://cloudflare-dns.com/dns-query";
        _fallback = fallback ?? "https://dns.quad9.net/dns-query";
    }

    public sealed record DnsResult(bool Resolved, bool Blocked, IReadOnlyList<string> Addresses, string Resolver);

    /// <summary>Resolves A records for a host, trying primary then fallback.</summary>
    public async Task<DnsResult> ResolveAsync(string host, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var viaPrimary = await QueryAsync(_primary, host, ct).ConfigureAwait(false);
        if (viaPrimary is not null)
        {
            return viaPrimary;
        }

        var viaFallback = await QueryAsync(_fallback, host, ct).ConfigureAwait(false);
        return viaFallback ?? new DnsResult(false, false, Array.Empty<string>(), "none");
    }

    private async Task<DnsResult?> QueryAsync(string resolver, string host, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));

            var url = $"{resolver}?name={Uri.EscapeDataString(host)}&type=A";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.ParseAdd("application/dns-json");

            using var response = await _http.SendAsync(request, cts.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token).ConfigureAwait(false);

            var status = doc.RootElement.TryGetProperty("Status", out var s) ? s.GetInt32() : -1;
            var addresses = new List<string>();
            if (doc.RootElement.TryGetProperty("Answer", out var answers) && answers.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in answers.EnumerateArray())
                {
                    if (a.TryGetProperty("data", out var data) && data.GetString() is { } ip)
                    {
                        addresses.Add(ip);
                    }
                }
            }

            // Cloudflare's malware filter answers 0.0.0.0 for blocked names.
            var blocked = addresses.Count == 1 && addresses[0] is "0.0.0.0" or "::";
            var resolved = status == 0 && addresses.Count > 0 && !blocked;
            var name = new Uri(resolver).Host;
            return new DnsResult(resolved, blocked, addresses, name);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _log.LogDebug(ex, "DoH query failed via {Resolver}.", resolver);
            return null;
        }
    }
}

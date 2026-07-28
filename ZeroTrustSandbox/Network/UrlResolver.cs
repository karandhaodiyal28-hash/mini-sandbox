using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace ZeroTrustSandbox.Network;

/// <summary>Result of un-shortening + sanitizing a URL.</summary>
public sealed class ResolvedUrl
{
    public required string Original { get; init; }
    public required string Final { get; init; }
    public required string Sanitized { get; init; }
    public IReadOnlyList<string> RedirectChain { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> StrippedParameters { get; init; } = Array.Empty<string>();
    public string? Host => Uri.TryCreate(Sanitized, UriKind.Absolute, out var u) ? u.Host : null;
}

/// <summary>
/// Resolves URL shorteners by following redirects in-memory (no rendering) and
/// strips tracking parameters (UTM, fbclid, gclid, affiliate tags, fragments).
/// </summary>
public sealed class UrlResolver
{
    private static readonly HashSet<string> ShortenerHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "goo.gl",
        "rebrand.ly", "cutt.ly", "t.ly", "shorturl.at", "rb.gy", "lnkd.in", "tiny.cc"
    };

    private static readonly string[] TrackingParams =
    [
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "dclid", "gclsrc", "msclkid", "mc_eid", "mc_cid",
        "ref", "ref_src", "referrer", "igshid", "vero_id", "yclid", "_hsenc",
        "_hsmi", "wickedid", "affid", "aff_id", "affiliate", "campaignid"
    ];

    private readonly HttpClient _http;
    private readonly ILogger<UrlResolver> _log;

    public UrlResolver(HttpClient http, ILogger<UrlResolver> log)
    {
        _http = http;
        _log = log;
    }

    public async Task<ResolvedUrl> ResolveAsync(string url, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var start) || start.Scheme is not ("http" or "https"))
        {
            return new ResolvedUrl { Original = url, Final = url, Sanitized = url };
        }

        var chain = new List<string> { start.ToString() };
        var current = start;

        // Only chase redirects for known shorteners (avoids extra requests and
        // avoids "pre-visiting" arbitrary untrusted endpoints).
        if (ShortenerHosts.Contains(current.Host))
        {
            for (var hop = 0; hop < 10; hop++)
            {
                var next = await GetRedirectTargetAsync(current, ct).ConfigureAwait(false);
                if (next is null || string.Equals(next.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                chain.Add(next.ToString());
                current = next;
            }
        }

        var (sanitized, stripped) = Sanitize(current);
        return new ResolvedUrl
        {
            Original = url,
            Final = current.ToString(),
            Sanitized = sanitized,
            RedirectChain = chain,
            StrippedParameters = stripped
        };
    }

    private async Task<Uri?> GetRedirectTargetAsync(Uri uri, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var request = new HttpRequestMessage(HttpMethod.Head, uri);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);

            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is not null)
            {
                var target = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location
                    : new Uri(uri, response.Headers.Location);

                // SSRF guard: never chase a shortener redirect into loopback /
                // private / link-local space (e.g. 127.0.0.1, 169.254.169.254
                // cloud-metadata, 10/172.16/192.168, ::1, fc00::/7).
                if (IsBlockedHop(target))
                {
                    _log.LogWarning("Blocked shortener redirect to internal address: {Host}.", target.Host);
                    return null;
                }
                return target;
            }
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _log.LogDebug(ex, "Redirect resolution failed for {Uri}.", uri);
            return null;
        }
    }

    /// <summary>
    /// True if a redirect target points at loopback / private / link-local /
    /// unique-local space (or a local-only hostname). Blocks SSRF-style probing
    /// of the user's own machine and LAN via attacker-controlled shortener hops.
    /// </summary>
    private static bool IsBlockedHop(Uri uri)
    {
        var host = uri.Host;
        if (host.Length == 0
            || host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host, out var ip))
        {
            return false; // hostname; resolved later inside the isolated renderer
        }
        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            return b[0] is 0 or 10 or 127
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254);
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
        }
        return false;
    }

    /// <summary>Removes tracking parameters and the fragment. Pure/testable.</summary>
    public static (string Sanitized, IReadOnlyList<string> Stripped) Sanitize(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var stripped = new List<string>();
        var builder = new UriBuilder(uri) { Fragment = string.Empty };

        if (!string.IsNullOrEmpty(uri.Query))
        {
            var kept = new List<string>();
            foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var key = pair.Split('=', 2)[0];
                var isTracking = TrackingParams.Contains(key, StringComparer.OrdinalIgnoreCase)
                                 || key.StartsWith("utm_", StringComparison.OrdinalIgnoreCase);
                if (isTracking)
                {
                    stripped.Add(key);
                }
                else
                {
                    kept.Add(pair);
                }
            }
            builder.Query = string.Join('&', kept);
        }

        return (builder.Uri.ToString(), stripped);
    }
}

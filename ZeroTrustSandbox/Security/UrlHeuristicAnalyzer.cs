using System.Net;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Fully-offline structural risk analysis of a URL. Produces real, varying
/// findings (scheme, host shape, TLD abuse, brand-keyword misuse, executable
/// links, etc.) so a target still gets a meaningful risk score even without an
/// API key or network reputation feeds.
/// </summary>
public sealed class UrlHeuristicAnalyzer
{
    private const string Src = "URL";

    // TLDs disproportionately abused for phishing/malware (incl. the "risky new"
    // gTLDs). Not exhaustive — just high-signal.
    private static readonly HashSet<string> HighAbuseTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work",
        "country", "gdn", "kim", "review", "party", "science", "stream", "download",
        "loan", "men", "rest", "fit", "cam", "quest", "sbs"
    };

    // Sensitive brand / action keywords frequently abused in phishing hostnames.
    private static readonly string[] BrandKeywords =
    [
        "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
        "instagram", "whatsapp", "outlook", "office365", "bank", "login", "signin",
        "secure", "verify", "account", "update", "wallet", "metamask", "coinbase"
    ];

    private static readonly string[] DangerousPathExtensions =
    [
        ".exe", ".scr", ".js", ".vbs", ".jar", ".apk", ".msi", ".bat", ".cmd",
        ".ps1", ".hta", ".dll", ".jse", ".wsf", ".lnk"
    ];

    /// <summary>Analyzes URL structure. Never touches the network.</summary>
    public IReadOnlyList<ThreatVerdict> Analyze(string url)
    {
        var verdicts = new List<ThreatVerdict>();
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return verdicts;
        }

        // 1) Transport security.
        if (string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            verdicts.Add(ThreatVerdict.Warn(Src, "Connection is not HTTPS — traffic can be read or modified in transit.", weight: 20));
        }
        else if (string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            verdicts.Add(ThreatVerdict.Safe(Src, "Uses HTTPS (encrypted transport)."));
        }

        var host = uri.Host;
        var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);

        // 2) Raw IP host.
        if (IPAddress.TryParse(host, out _))
        {
            verdicts.Add(ThreatVerdict.Warn(Src, "Host is a raw IP address instead of a domain name (common in phishing/malware C2).", weight: 40));
        }

        // 3) Punycode / IDN homograph.
        if (host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
        {
            verdicts.Add(ThreatVerdict.Warn(Src, "Internationalized (punycode) domain — possible homograph spoofing.", weight: 40));
        }

        // 4) Embedded credentials (user:pass@host) — obfuscation trick.
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            verdicts.Add(ThreatVerdict.Warn(Src, "URL embeds credentials/userinfo before the host (obfuscation).", weight: 45));
        }

        // 5) Non-standard port.
        if (!uri.IsDefaultPort)
        {
            verdicts.Add(ThreatVerdict.Warn(Src, $"Connects on a non-standard port ({uri.Port}).", weight: 20));
        }

        // 6) Deep subdomain nesting.
        if (labels.Length >= 5)
        {
            verdicts.Add(ThreatVerdict.Warn(Src, $"Unusually deep subdomain nesting ({labels.Length} labels).", weight: 25));
        }

        // 7) High-abuse TLD.
        if (labels.Length >= 1 && HighAbuseTlds.Contains(labels[^1]))
        {
            verdicts.Add(ThreatVerdict.Warn(Src, $"High-abuse top-level domain '.{labels[^1].ToLowerInvariant()}'.", weight: 30));
        }

        // 8) Brand/keyword misuse: keyword appears in host but the registrable
        //    label is not exactly that brand (e.g. "paypal-secure.xyz").
        var sld = labels.Length >= 2 ? labels[^2] : (labels.Length == 1 ? labels[0] : string.Empty);
        foreach (var kw in BrandKeywords)
        {
            if (host.Contains(kw, StringComparison.OrdinalIgnoreCase) &&
                !sld.Equals(kw, StringComparison.OrdinalIgnoreCase))
            {
                verdicts.Add(ThreatVerdict.Warn(Src, $"Sensitive keyword '{kw}' appears in an unrelated domain — verify this is the real site.", weight: 40));
                break;
            }
        }

        // 9) Direct link to an executable/script.
        var path = uri.AbsolutePath.ToLowerInvariant();
        if (DangerousPathExtensions.Any(ext => path.EndsWith(ext, StringComparison.Ordinal)))
        {
            verdicts.Add(ThreatVerdict.Warn(Src, "URL points directly to an executable or script download.", weight: 50));
        }

        // 10) Excessively long URL (obfuscation / redirect stuffing).
        if (url.Length > 150)
        {
            verdicts.Add(ThreatVerdict.Warn(Src, $"Unusually long URL ({url.Length} chars).", weight: 15));
        }

        return verdicts;
    }
}

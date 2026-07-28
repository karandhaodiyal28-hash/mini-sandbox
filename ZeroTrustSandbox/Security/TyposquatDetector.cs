using System.Globalization;
using System.IO;
using System.Text;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Fully offline detection of typosquatting and IDN homograph attacks. Compares
/// a candidate domain against a list of high-value domains using Levenshtein
/// distance and a Unicode confusable-character map.
/// </summary>
public sealed class TyposquatDetector
{
    private const string Src = "Anti-Phishing";
    private readonly HashSet<string> _topDomains;

    public TyposquatDetector(IEnumerable<string> topDomains)
    {
        ArgumentNullException.ThrowIfNull(topDomains);
        _topDomains = new HashSet<string>(
            topDomains.Select(d => d.Trim().ToLowerInvariant()).Where(d => d.Length > 0),
            StringComparer.Ordinal);
    }

    /// <summary>Loads a newline-delimited domain list (e.g. top 10k). Safe if missing.</summary>
    public static TyposquatDetector FromFile(string path)
    {
        if (File.Exists(path))
        {
            try
            {
                return new TyposquatDetector(File.ReadLines(path));
            }
            catch (IOException)
            {
                // fall through to defaults
            }
        }
        return new TyposquatDetector(DefaultTopDomains);
    }

    public IReadOnlyList<ThreatVerdict> Analyze(string host)
    {
        var findings = new List<ThreatVerdict>();
        if (string.IsNullOrWhiteSpace(host))
        {
            return findings;
        }

        host = host.Trim().TrimEnd('.').ToLowerInvariant();

        // 1) IDN / homograph detection ---------------------------------------
        var hasNonAscii = host.Any(c => c > 127);
        var isPunycode = host.Contains("xn--", StringComparison.Ordinal);
        if (hasNonAscii || isPunycode)
        {
            var skeleton = Skeletonize(hasNonAscii ? host : DecodePunycodeSafe(host));
            findings.Add(ThreatVerdict.Warn(Src,
                "Domain uses non-ASCII/IDN characters (possible homograph attack).",
                weight: 50, detail: $"skeleton={skeleton}"));

            foreach (var top in _topDomains)
            {
                if (!string.Equals(skeleton, top, StringComparison.Ordinal) &&
                    Skeletonize(top) == skeleton)
                {
                    findings.Add(ThreatVerdict.Danger(Src,
                        $"Visually impersonates '{top}' via confusable characters.", weight: 90));
                    break;
                }
            }
        }

        // 2) Typosquatting via edit distance ---------------------------------
        var registrable = RegistrableLabel(host);
        foreach (var top in _topDomains)
        {
            var topLabel = RegistrableLabel(top);
            if (registrable == topLabel)
            {
                return findings; // exact known-good label, stop early
            }

            var distance = Levenshtein(registrable, topLabel);
            if (distance is > 0 and <= 2 && Math.Abs(registrable.Length - topLabel.Length) <= 2 && topLabel.Length >= 4)
            {
                findings.Add(ThreatVerdict.Warn(Src,
                    $"Looks like a typo of '{top}' (edit distance {distance}).",
                    weight: 65, detail: $"candidate={registrable}"));
                break;
            }
        }

        return findings;
    }

    /// <summary>Classic Levenshtein edit distance.</summary>
    public static int Levenshtein(string a, string b)
    {
        if (a == b)
        {
            return 0;
        }
        if (a.Length == 0)
        {
            return b.Length;
        }
        if (b.Length == 0)
        {
            return a.Length;
        }

        var prev = new int[b.Length + 1];
        var curr = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++)
        {
            prev[j] = j;
        }

        for (var i = 1; i <= a.Length; i++)
        {
            curr[0] = i;
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                curr[j] = Math.Min(Math.Min(prev[j] + 1, curr[j - 1] + 1), prev[j - 1] + cost);
            }
            (prev, curr) = (curr, prev);
        }
        return prev[b.Length];
    }

    /// <summary>Maps confusable Unicode characters to a canonical ASCII skeleton.</summary>
    public static string Skeletonize(string input)
    {
        var normalized = input.Normalize(NormalizationForm.FormKD);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            sb.Append(Confusables.TryGetValue(ch, out var mapped) ? mapped : ch);
        }
        return sb.ToString().ToLowerInvariant();
    }

    private static string RegistrableLabel(string host)
    {
        // Best-effort: take the second-level label (e.g. paypal from paypal.com).
        var parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? parts[^2] : host;
    }

    private static string DecodePunycodeSafe(string host)
    {
        try
        {
            return new IdnMapping().GetUnicode(host);
        }
        catch (ArgumentException)
        {
            return host;
        }
    }

    private static readonly Dictionary<char, char> Confusables = new()
    {
        ['\u0430'] = 'a', // Cyrillic a
        ['\u0435'] = 'e', // Cyrillic e
        ['\u043e'] = 'o', // Cyrillic o
        ['\u0440'] = 'p', // Cyrillic er
        ['\u0441'] = 'c', // Cyrillic es
        ['\u0445'] = 'x', // Cyrillic ha
        ['\u0455'] = 's', // Cyrillic dze
        ['\u0456'] = 'i', // Cyrillic byelorussian-ukrainian i
        ['\u0491'] = 'r',
        ['\u03bf'] = 'o', // Greek omicron
        ['\u0261'] = 'g',
        ['\u2010'] = '-',
        ['\u04cf'] = 'l',
        ['0'] = 'o',
        ['1'] = 'l',
        ['5'] = 's',
    };

    private static readonly string[] DefaultTopDomains =
    [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
        "microsoft.com", "paypal.com", "netflix.com", "instagram.com", "linkedin.com",
        "twitter.com", "wikipedia.org", "yahoo.com", "office.com", "live.com",
        "outlook.com", "github.com", "dropbox.com", "adobe.com", "chase.com",
        "wellsfargo.com", "bankofamerica.com", "citibank.com", "coinbase.com", "binance.com",
        "steamcommunity.com", "whatsapp.com", "gmail.com", "icloud.com", "twitch.tv",
    ];
}

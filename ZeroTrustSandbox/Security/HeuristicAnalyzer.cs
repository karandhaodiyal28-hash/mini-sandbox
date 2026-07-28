using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Fully offline heuristic analysis of file bytes: magic-byte vs extension
/// validation, Shannon entropy (packed/encrypted detection), suspicious string
/// extraction and lightweight PE header inspection.
/// </summary>
public sealed partial class HeuristicAnalyzer
{
    private const double HighEntropyThreshold = 7.5;
    private const string Src = "Heuristics";

    private static readonly Dictionary<string, byte[][]> MagicBytes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".pdf"] = [[0x25, 0x50, 0x44, 0x46]],                       // %PDF
        [".png"] = [[0x89, 0x50, 0x4E, 0x47]],
        [".jpg"] = [[0xFF, 0xD8, 0xFF]],
        [".jpeg"] = [[0xFF, 0xD8, 0xFF]],
        [".gif"] = [[0x47, 0x49, 0x46, 0x38]],                       // GIF8
        [".zip"] = [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06]],
        [".docx"] = [[0x50, 0x4B, 0x03, 0x04]],
        [".xlsx"] = [[0x50, 0x4B, 0x03, 0x04]],
        [".pptx"] = [[0x50, 0x4B, 0x03, 0x04]],
        [".rar"] = [[0x52, 0x61, 0x72, 0x21]],                       // Rar!
        [".7z"] = [[0x37, 0x7A, 0xBC, 0xAF]],
        [".gz"] = [[0x1F, 0x8B]],
        [".exe"] = [[0x4D, 0x5A]],                                    // MZ
        [".dll"] = [[0x4D, 0x5A]],
        [".rtf"] = [[0x7B, 0x5C, 0x72, 0x74, 0x66]],                 // {\rtf
    };

    // File types that are ALREADY compressed/encoded by design — high Shannon
    // entropy is normal for these, so it must NOT be treated as a "packed/
    // encrypted" red flag (that was inflating every such file's score).
    private static readonly HashSet<string> ExpectedHighEntropy = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".gz", ".rar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"
    };

    /// <summary>Analyzes an in-memory buffer. Never touches disk.</summary>
    public IReadOnlyList<ThreatVerdict> Analyze(ReadOnlySpan<byte> data, string fileName)
    {
        var verdicts = new List<ThreatVerdict>();
        var ext = GetExtension(fileName);

        // 1) Magic byte vs extension mismatch --------------------------------
        if (!string.IsNullOrEmpty(ext) && MagicBytes.TryGetValue(ext, out var signatures))
        {
            var matched = false;
            foreach (var sig in signatures)
            {
                if (StartsWith(data, sig))
                {
                    matched = true;
                    break;
                }
            }
            verdicts.Add(matched
                ? ThreatVerdict.Safe(Src, $"File header matches extension ({ext}).")
                : ThreatVerdict.Warn(Src, $"File header does NOT match extension {ext} (possible masquerading).", weight: 55));
        }

        // Detect an EXE masquerading under a document extension.
        if (StartsWith(data, [0x4D, 0x5A]) && ext is not (".exe" or ".dll" or ".sys" or ".scr"))
        {
            verdicts.Add(ThreatVerdict.Danger(Src, $"Windows executable (MZ) disguised as '{ext}'.", weight: 80));
        }

        // 2) Shannon entropy -------------------------------------------------
        var entropy = ShannonEntropy(data);
        var expectedCompressed = ExpectedHighEntropy.Contains(ext);
        if (entropy > HighEntropyThreshold && !expectedCompressed)
        {
            verdicts.Add(ThreatVerdict.Warn(Src,
                $"High entropy ({entropy:F2}/8.0) suggests packed or encrypted content.",
                weight: 45, detail: $"entropy={entropy:F4}"));
        }
        else
        {
            verdicts.Add(ThreatVerdict.Info(Src, expectedCompressed
                ? $"Entropy {entropy:F2}/8.0 (expected for compressed {ext})."
                : $"Entropy {entropy:F2}/8.0 (normal)."));
        }

        // 3) Suspicious string extraction -----------------------------------
        foreach (var v in ScanStrings(data))
        {
            verdicts.Add(v);
        }

        // 4) PE header analysis ---------------------------------------------
        if (StartsWith(data, [0x4D, 0x5A]))
        {
            verdicts.AddRange(AnalyzePe(data));
        }

        return verdicts;
    }

    /// <summary>Computes Shannon entropy (bits/byte, 0-8) over the buffer.</summary>
    public static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0d;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        double entropy = 0d;
        double len = data.Length;
        foreach (var c in counts)
        {
            if (c == 0)
            {
                continue;
            }
            var p = c / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static IEnumerable<ThreatVerdict> ScanStrings(ReadOnlySpan<byte> data)
    {
        // Extract printable ASCII runs (>= 5 chars) and pattern-match them.
        var sb = new StringBuilder();
        var text = new StringBuilder(Math.Min(data.Length, 1 << 20));
        foreach (var b in data.Length > (1 << 20) ? data[..(1 << 20)] : data)
        {
            if (b is >= 0x20 and < 0x7F)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= 5)
                {
                    text.Append(sb).Append('\n');
                }
                sb.Clear();
            }
        }
        if (sb.Length >= 5)
        {
            text.Append(sb);
        }

        var haystack = text.ToString();
        var findings = new List<ThreatVerdict>();

        if (SuspiciousApiRegex().IsMatch(haystack))
        {
            findings.Add(ThreatVerdict.Warn(Src, "Contains process-injection / shell API strings.", weight: 50));
        }
        var urls = UrlRegex().Matches(haystack);
        if (urls.Count > 0)
        {
            findings.Add(ThreatVerdict.Info(Src, $"Embedded URLs found: {urls.Count}.",
                string.Join(", ", urls.Take(5).Select(m => m.Value))));
        }
        if (RegistryRunKeyRegex().IsMatch(haystack))
        {
            findings.Add(ThreatVerdict.Warn(Src, "References registry Run/persistence keys.", weight: 45));
        }
        return findings;
    }

    private static IEnumerable<ThreatVerdict> AnalyzePe(ReadOnlySpan<byte> data)
    {
        var results = new List<ThreatVerdict>();
        if (data.Length < 0x40)
        {
            return results;
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3C, 4));
        if (peOffset <= 0 || peOffset + 24 > data.Length)
        {
            return results;
        }
        // PE\0\0 signature check.
        if (!(data[peOffset] == 'P' && data[peOffset + 1] == 'E' && data[peOffset + 2] == 0 && data[peOffset + 3] == 0))
        {
            return results;
        }

        var coff = peOffset + 4;
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 2, 2));
        var timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(coff + 4, 4));
        var compile = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp).UtcDateTime;

        results.Add(ThreatVerdict.Info(Src, $"PE image: {numberOfSections} sections, compiled {compile:yyyy-MM-dd}."));

        if (timeDateStamp == 0 || compile > DateTime.UtcNow.AddDays(1) || compile.Year < 2000)
        {
            results.Add(ThreatVerdict.Warn(Src, "PE compile timestamp is zeroed or implausible (tampered).", weight: 40));
        }
        if (numberOfSections is 0 or > 12)
        {
            results.Add(ThreatVerdict.Warn(Src, $"Unusual PE section count ({numberOfSections}).", weight: 35));
        }
        return results;
    }

    private static bool StartsWith(ReadOnlySpan<byte> data, byte[] prefix)
        => data.Length >= prefix.Length && data[..prefix.Length].SequenceEqual(prefix);

    private static string GetExtension(string fileName)
    {
        var dot = fileName.LastIndexOf('.');
        return dot < 0 ? string.Empty : fileName[dot..].ToLowerInvariant();
    }

    [GeneratedRegex(@"\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|LoadLibraryA?|GetProcAddress|WinExec|ShellExecute|URLDownloadToFile|powershell|cmd\.exe|rundll32)\b", RegexOptions.IgnoreCase)]
    private static partial Regex SuspiciousApiRegex();

    [GeneratedRegex(@"https?://[^\s""'<>]{4,}", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"(CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce)", RegexOptions.IgnoreCase)]
    private static partial Regex RegistryRunKeyRegex();
}

using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// A dependency-free, pure-managed YARA-<em>lite</em> engine. It parses a
/// practical subset of the YARA rule language so community rule files can be
/// dropped into the resources folder without shipping the native libyara.dll.
/// </summary>
/// <remarks>
/// Supported per rule:
/// <list type="bullet">
/// <item>text strings: <c>$a = "value" [nocase] [ascii] [wide]</c></item>
/// <item>hex strings: <c>$h = { DE AD BE EF ?? }</c> (wildcards allowed)</item>
/// <item>regex strings: <c>$r = /pattern/</c></item>
/// <item>conditions: <c>any of them</c>, <c>all of them</c>, <c>N of them</c>,
/// or a boolean combination of individual <c>$id</c> identifiers with and/or.</item>
/// </list>
/// Anything more advanced is ignored gracefully rather than throwing.
/// </remarks>
public sealed partial class YaraScanner
{
    private readonly List<YaraRule> _rules = new();

    public int RuleCount => _rules.Count;

    /// <summary>Loads every *.yar / *.yara file in a directory. Safe if missing.</summary>
    public void LoadRulesFromDirectory(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(directory, "*.yar*", SearchOption.AllDirectories))
        {
            try
            {
                LoadRules(File.ReadAllText(file));
            }
            catch (IOException)
            {
                // Skip unreadable rule files.
            }
        }
    }

    /// <summary>Parses rules from raw text and adds them to the engine.</summary>
    public void LoadRules(string ruleText)
    {
        if (string.IsNullOrWhiteSpace(ruleText))
        {
            return;
        }

        foreach (Match rule in RuleBlockRegex().Matches(ruleText))
        {
            var name = rule.Groups["name"].Value;
            var body = rule.Groups["body"].Value;
            var parsed = ParseRule(name, body);
            if (parsed is not null)
            {
                _rules.Add(parsed);
            }
        }
    }

    /// <summary>Scans a buffer, returning one verdict per matched rule.</summary>
    public IReadOnlyList<ThreatVerdict> Scan(ReadOnlySpan<byte> data)
    {
        // Build an ASCII+latin1 text view once for text/regex matching.
        var text = Latin1(data);
        var results = new List<ThreatVerdict>();

        foreach (var rule in _rules)
        {
            var matchedIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var pattern in rule.Strings)
            {
                if (pattern.IsMatch(data, text))
                {
                    matchedIds.Add(pattern.Id);
                }
            }

            if (rule.Evaluate(matchedIds))
            {
                var weight = rule.Meta.TryGetValue("severity", out var sev)
                    && int.TryParse(sev, NumberStyles.Integer, CultureInfo.InvariantCulture, out var w)
                    ? Math.Clamp(w, 1, 100) : 85;
                results.Add(ThreatVerdict.Danger("YARA-lite", $"Matched rule '{rule.Name}'.", weight,
                    detail: string.Join(",", matchedIds)));
            }
        }
        return results;
    }

    private static string Latin1(ReadOnlySpan<byte> data)
    {
        var max = Math.Min(data.Length, 8 * 1024 * 1024);
        return Encoding.Latin1.GetString(data[..max]);
    }

    private static YaraRule? ParseRule(string name, string body)
    {
        var rule = new YaraRule(name);

        // meta
        var meta = MetaSectionRegex().Match(body);
        if (meta.Success)
        {
            foreach (Match m in MetaEntryRegex().Matches(meta.Groups["meta"].Value))
            {
                rule.Meta[m.Groups["k"].Value] = m.Groups["v"].Value;
            }
        }

        // strings
        foreach (Match s in TextStringRegex().Matches(body))
        {
            var mods = s.Groups["mods"].Value;
            rule.Strings.Add(YaraPattern.Text(
                s.Groups["id"].Value,
                Unescape(s.Groups["val"].Value),
                nocase: mods.Contains("nocase", StringComparison.OrdinalIgnoreCase),
                wide: mods.Contains("wide", StringComparison.OrdinalIgnoreCase)));
        }
        foreach (Match s in HexStringRegex().Matches(body))
        {
            var pattern = YaraPattern.Hex(s.Groups["id"].Value, s.Groups["hex"].Value);
            if (pattern is not null)
            {
                rule.Strings.Add(pattern);
            }
        }
        foreach (Match s in RegexStringRegex().Matches(body))
        {
            var pattern = YaraPattern.Regex(s.Groups["id"].Value, s.Groups["rx"].Value);
            if (pattern is not null)
            {
                rule.Strings.Add(pattern);
            }
        }

        var cond = ConditionRegex().Match(body);
        rule.Condition = cond.Success ? cond.Groups["cond"].Value.Trim() : "any of them";

        return rule.Strings.Count > 0 ? rule : null;
    }

    private static string Unescape(string s) =>
        s.Replace("\\\\", "\\", StringComparison.Ordinal)
         .Replace("\\\"", "\"", StringComparison.Ordinal)
         .Replace("\\n", "\n", StringComparison.Ordinal)
         .Replace("\\t", "\t", StringComparison.Ordinal);

    [GeneratedRegex(@"rule\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^\{]*)?\{(?<body>.*?)\}\s*(?=rule\s|$)", RegexOptions.Singleline)]
    private static partial Regex RuleBlockRegex();

    [GeneratedRegex(@"meta\s*:(?<meta>.*?)(strings\s*:|condition\s*:)", RegexOptions.Singleline)]
    private static partial Regex MetaSectionRegex();

    [GeneratedRegex(@"(?<k>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*""(?<v>[^""]*)""")]
    private static partial Regex MetaEntryRegex();

    [GeneratedRegex(@"(?<id>\$[A-Za-z0-9_]*)\s*=\s*""(?<val>(?:\\.|[^""\\])*)""(?<mods>(?:\s+(?:nocase|wide|ascii|fullword))*)", RegexOptions.None)]
    private static partial Regex TextStringRegex();

    [GeneratedRegex(@"(?<id>\$[A-Za-z0-9_]*)\s*=\s*\{(?<hex>[0-9A-Fa-f\?\s]+)\}")]
    private static partial Regex HexStringRegex();

    [GeneratedRegex(@"(?<id>\$[A-Za-z0-9_]*)\s*=\s*/(?<rx>(?:\\.|[^/\\])+)/")]
    private static partial Regex RegexStringRegex();

    [GeneratedRegex(@"condition\s*:(?<cond>.*?)$", RegexOptions.Singleline)]
    private static partial Regex ConditionRegex();
}

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ZeroTrustSandbox.Security;

/// <summary>A single parsed YARA-lite rule.</summary>
internal sealed class YaraRule
{
    public YaraRule(string name) => Name = name;

    public string Name { get; }
    public Dictionary<string, string> Meta { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<YaraPattern> Strings { get; } = new();
    public string Condition { get; set; } = "any of them";

    /// <summary>Evaluates the (subset) condition against the matched string ids.</summary>
    public bool Evaluate(ISet<string> matched)
    {
        var cond = Condition.Trim();

        if (cond.Equals("any of them", StringComparison.OrdinalIgnoreCase))
        {
            return matched.Count > 0;
        }
        if (cond.Equals("all of them", StringComparison.OrdinalIgnoreCase))
        {
            return matched.Count == Strings.Count && Strings.Count > 0;
        }

        // "N of them"
        var nOfThem = Regex.Match(cond, @"^(?<n>\d+)\s+of\s+them$", RegexOptions.IgnoreCase);
        if (nOfThem.Success)
        {
            var n = int.Parse(nOfThem.Groups["n"].Value, CultureInfo.InvariantCulture);
            return matched.Count >= n;
        }

        // Boolean combination of explicit identifiers, e.g. "$a and ($b or $c)".
        // We ignore parentheses precedence subtleties: OR binds loosest.
        foreach (var orClause in Regex.Split(cond, @"\bor\b", RegexOptions.IgnoreCase))
        {
            var ids = Regex.Matches(orClause, @"\$[A-Za-z0-9_]*")
                           .Select(m => m.Value)
                           .Where(id => id.Length > 1)
                           .ToList();
            if (ids.Count == 0)
            {
                continue;
            }
            var hasNot = Regex.IsMatch(orClause, @"\bnot\b", RegexOptions.IgnoreCase);
            var allMatched = ids.All(matched.Contains);
            if (hasNot ? !allMatched : allMatched)
            {
                return true;
            }
        }

        // Fallback: treat like "any of them".
        return matched.Count > 0 && !Regex.IsMatch(cond, @"\$");
    }
}

/// <summary>Kinds of matchable pattern.</summary>
internal enum YaraPatternKind
{
    Text,
    Hex,
    Regex
}

/// <summary>One string/hex/regex pattern belonging to a <see cref="YaraRule"/>.</summary>
internal sealed class YaraPattern
{
    private readonly YaraPatternKind _kind;
    private readonly string? _text;
    private readonly bool _nocase;
    private readonly bool _wide;
    private readonly byte?[]? _hex; // null element == wildcard byte
    private readonly Regex? _regex;

    public string Id { get; }

    private YaraPattern(string id, YaraPatternKind kind, string? text, bool nocase, bool wide, byte?[]? hex, Regex? regex)
    {
        Id = id;
        _kind = kind;
        _text = text;
        _nocase = nocase;
        _wide = wide;
        _hex = hex;
        _regex = regex;
    }

    public static YaraPattern Text(string id, string value, bool nocase, bool wide)
        => new(id, YaraPatternKind.Text, value, nocase, wide, null, null);

    public static YaraPattern? Hex(string id, string hex)
    {
        var tokens = hex.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var bytes = new List<byte?>(tokens.Length);
        foreach (var token in tokens)
        {
            if (token == "??")
            {
                bytes.Add(null);
            }
            else if (token.Length == 2 && byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                bytes.Add(b);
            }
            else
            {
                return null; // unsupported token (nibble wildcard / jumps) -> skip rule string
            }
        }
        return bytes.Count == 0 ? null : new YaraPattern(id, YaraPatternKind.Hex, null, false, false, bytes.ToArray(), null);
    }

    public static YaraPattern? Regex(string id, string pattern)
    {
        try
        {
            var rx = new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
            return new YaraPattern(id, YaraPatternKind.Regex, null, false, false, null, rx);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    public bool IsMatch(ReadOnlySpan<byte> data, string text)
    {
        switch (_kind)
        {
            case YaraPatternKind.Text:
                var cmp = _nocase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                if (text.Contains(_text!, cmp))
                {
                    return true;
                }
                if (_wide)
                {
                    // Match UTF-16LE representation by inserting null bytes.
                    var wide = string.Join('\0', _text!.ToCharArray()) + "\0";
                    return text.Contains(wide, cmp);
                }
                return false;

            case YaraPatternKind.Hex:
                return IndexOfHex(data) >= 0;

            case YaraPatternKind.Regex:
                try
                {
                    return _regex!.IsMatch(text);
                }
                catch (RegexMatchTimeoutException)
                {
                    return false;
                }

            default:
                return false;
        }
    }

    private int IndexOfHex(ReadOnlySpan<byte> data)
    {
        var pattern = _hex!;
        if (pattern.Length == 0 || data.Length < pattern.Length)
        {
            return -1;
        }
        var last = data.Length - pattern.Length;
        for (var i = 0; i <= last; i++)
        {
            var ok = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                var expected = pattern[j];
                if (expected.HasValue && data[i + j] != expected.Value)
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
            {
                return i;
            }
        }
        return -1;
    }
}

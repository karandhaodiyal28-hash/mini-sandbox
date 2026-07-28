using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace ZeroTrustSandbox.Data;

/// <summary>
/// Manages user-defined and feed-imported blocklists (domains, IPs, file
/// hashes and regex URL patterns). Entries live in SQLite; an in-memory
/// snapshot is kept for fast per-request matching.
/// </summary>
public sealed class BlocklistManager
{
    private readonly DatabaseContext _db;
    private readonly HashSet<string> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ips = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Regex> _patterns = new();
    private readonly ReaderWriterLockSlim _lock = new();

    public BlocklistManager(DatabaseContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    public async Task LoadAsync(CancellationToken ct = default)
    {
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT type, value FROM blocklist;";
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);

        _lock.EnterWriteLock();
        try
        {
            _domains.Clear();
            _ips.Clear();
            _hashes.Clear();
            _patterns.Clear();
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                Index(reader.GetString(0), reader.GetString(1));
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    private void Index(string type, string value)
    {
        switch (type)
        {
            case "domain": _domains.Add(value); break;
            case "ip": _ips.Add(value); break;
            case "hash": _hashes.Add(value); break;
            case "regex":
                try { _patterns.Add(new Regex(value, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1))); }
                catch (ArgumentException) { /* skip invalid pattern */ }
                break;
        }
    }

    public bool IsHostBlocked(string host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return false;
        }
        _lock.EnterReadLock();
        try
        {
            if (_domains.Contains(host))
            {
                return true;
            }
            // match parent domains (sub.evil.com -> evil.com)
            var idx = host.IndexOf('.');
            while (idx >= 0 && idx < host.Length - 1)
            {
                if (_domains.Contains(host[(idx + 1)..]))
                {
                    return true;
                }
                idx = host.IndexOf('.', idx + 1);
            }
            return false;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public bool IsUrlBlocked(string url)
    {
        _lock.EnterReadLock();
        try
        {
            foreach (var rx in _patterns)
            {
                try
                {
                    if (rx.IsMatch(url))
                    {
                        return true;
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    // treat timeout as non-match
                }
            }
            return false;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public bool IsHashBlocked(string sha256)
    {
        _lock.EnterReadLock();
        try
        {
            return _hashes.Contains(sha256);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public async Task AddAsync(string type, string value, string source = "user", CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(type);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO blocklist (type, value, source, added_utc) VALUES ($t, $v, $s, $d)
            ON CONFLICT(type, value) DO NOTHING;
            """;
        cmd.Parameters.AddWithValue("$t", type);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.Parameters.AddWithValue("$s", source);
        cmd.Parameters.AddWithValue("$d", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);

        _lock.EnterWriteLock();
        try
        {
            Index(type, value);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>Imports a hosts-file style blocklist (e.g. StevenBlack/hosts).</summary>
    public async Task ImportHostsFileAsync(string content, string source, CancellationToken ct = default)
    {
        foreach (var raw in content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw.StartsWith('#'))
            {
                continue;
            }
            // "0.0.0.0 evil.com" or "127.0.0.1 evil.com"
            var parts = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var domain = parts.Length switch
            {
                2 when parts[0] is "0.0.0.0" or "127.0.0.1" => parts[1],
                1 => parts[0],
                _ => null
            };
            if (!string.IsNullOrWhiteSpace(domain) && domain.Contains('.', StringComparison.Ordinal))
            {
                await AddAsync("domain", domain, source, ct).ConfigureAwait(false);
            }
        }
    }
}

using System.Globalization;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Data;

/// <summary>
/// SQLite-backed cache for scan results plus the VirusTotal daily quota
/// counter and rolling threat-intelligence statistics.
/// </summary>
public sealed class CacheManager
{
    private readonly DatabaseContext _db;

    public CacheManager(DatabaseContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    private static string DayKey(DateTimeOffset utc) => utc.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    // ---- Scan result cache (24h TTL by default) -------------------------

    public async Task<ScanResult?> TryGetAsync(string key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT result_json, expires_utc FROM scan_cache WHERE key = $k LIMIT 1;";
        cmd.Parameters.AddWithValue("$k", key);

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            return null;
        }

        var expires = DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        if (expires <= DateTimeOffset.UtcNow)
        {
            return null; // expired; leave for periodic purge
        }

        var json = reader.GetString(0);
        var result = JsonConvert.DeserializeObject<ScanResult>(json);
        if (result is not null)
        {
            result.FromCache = true;
            await IncrementStatAsync("cache_hits", 1, ct).ConfigureAwait(false);
        }
        return result;
    }

    public async Task StoreAsync(string key, ScanResult result, int ttlHours, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(result);

        var now = DateTimeOffset.UtcNow;
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_cache (key, target, kind, level, risk_score, result_json, created_utc, expires_utc)
            VALUES ($k, $t, $kind, $lvl, $score, $json, $created, $expires)
            ON CONFLICT(key) DO UPDATE SET
                level = excluded.level,
                risk_score = excluded.risk_score,
                result_json = excluded.result_json,
                created_utc = excluded.created_utc,
                expires_utc = excluded.expires_utc;
            """;
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$t", result.Target);
        cmd.Parameters.AddWithValue("$kind", (int)result.Kind);
        cmd.Parameters.AddWithValue("$lvl", (int)result.Level);
        cmd.Parameters.AddWithValue("$score", result.RiskScore);
        cmd.Parameters.AddWithValue("$json", JsonConvert.SerializeObject(result));
        cmd.Parameters.AddWithValue("$created", now.ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$expires", now.AddHours(Math.Max(1, ttlHours)).ToString("o", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task PurgeExpiredAsync(CancellationToken ct = default)
    {
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scan_cache WHERE expires_utc <= $now;";
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    // ---- VirusTotal daily quota (auto-resets each UTC day) --------------

    public async Task<int> GetDailyUsageAsync(CancellationToken ct = default)
    {
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT count FROM api_usage WHERE day = $d LIMIT 1;";
        cmd.Parameters.AddWithValue("$d", DayKey(DateTimeOffset.UtcNow));
        var value = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return value is long l ? (int)l : 0;
    }

    public async Task<bool> TryConsumeDailyQuotaAsync(int dailyLimit, CancellationToken ct = default)
    {
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct).ConfigureAwait(false);

        var day = DayKey(DateTimeOffset.UtcNow);
        await using (var read = conn.CreateCommand())
        {
            read.Transaction = tx;
            read.CommandText = "SELECT count FROM api_usage WHERE day = $d LIMIT 1;";
            read.Parameters.AddWithValue("$d", day);
            var current = await read.ExecuteScalarAsync(ct).ConfigureAwait(false) is long l ? (int)l : 0;
            if (current >= dailyLimit)
            {
                await tx.RollbackAsync(ct).ConfigureAwait(false);
                return false;
            }
        }

        await using (var upsert = conn.CreateCommand())
        {
            upsert.Transaction = tx;
            upsert.CommandText = """
                INSERT INTO api_usage (day, count) VALUES ($d, 1)
                ON CONFLICT(day) DO UPDATE SET count = count + 1;
                """;
            upsert.Parameters.AddWithValue("$d", day);
            await upsert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await tx.CommitAsync(ct).ConfigureAwait(false);
        return true;
    }

    // ---- Statistics / threat families ----------------------------------

    public async Task IncrementStatAsync(string name, long by = 1, CancellationToken ct = default)
    {
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO stats (name, value) VALUES ($n, $v)
            ON CONFLICT(name) DO UPDATE SET value = value + $v;
            """;
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$v", by);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyDictionary<string, long>> GetStatsAsync(CancellationToken ct = default)
    {
        var result = new Dictionary<string, long>(StringComparer.Ordinal);
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name, value FROM stats;";
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result[reader.GetString(0)] = reader.GetInt64(1);
        }
        return result;
    }

    public async Task RecordThreatFamilyAsync(string family, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(family))
        {
            return;
        }
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO threat_families (family, hits) VALUES ($f, 1)
            ON CONFLICT(family) DO UPDATE SET hits = hits + 1;
            """;
        cmd.Parameters.AddWithValue("$f", family);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<(string Family, long Hits)>> GetTopThreatsAsync(int top = 10, CancellationToken ct = default)
    {
        var list = new List<(string, long)>();
        await using var conn = new SqliteConnection(_db.ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT family, hits FROM threat_families ORDER BY hits DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", top);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            list.Add((reader.GetString(0), reader.GetInt64(1)));
        }
        return list;
    }
}

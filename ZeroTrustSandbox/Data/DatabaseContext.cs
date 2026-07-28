using Microsoft.Data.Sqlite;
using ZeroTrustSandbox.Common;

namespace ZeroTrustSandbox.Data;

/// <summary>
/// Owns the single SQLite connection string and performs schema creation /
/// migration. All other data classes borrow short-lived connections from here
/// so the file is never held open longer than a query needs.
/// </summary>
public sealed class DatabaseContext
{
    public string ConnectionString { get; }

    public DatabaseContext(string? databaseFile = null)
    {
        var file = databaseFile ?? AppPaths.DatabaseFile;
        ConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = file,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        }.ToString();
    }

    public SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    /// <summary>Creates all tables if they do not already exist. Idempotent.</summary>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var conn = new SqliteConnection(ConnectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = Schema;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS scan_cache (
            key          TEXT PRIMARY KEY,
            target       TEXT NOT NULL,
            kind         INTEGER NOT NULL,
            level        INTEGER NOT NULL,
            risk_score   INTEGER NOT NULL,
            result_json  TEXT NOT NULL,
            created_utc  TEXT NOT NULL,
            expires_utc  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_usage (
            day          TEXT PRIMARY KEY,   -- yyyy-MM-dd (UTC)
            count        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stats (
            name         TEXT PRIMARY KEY,
            value        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threat_families (
            family       TEXT PRIMARY KEY,
            hits         INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blocklist (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            type         TEXT NOT NULL,      -- domain | ip | hash | regex
            value        TEXT NOT NULL,
            source       TEXT NOT NULL,      -- user | feed name
            added_utc    TEXT NOT NULL,
            UNIQUE(type, value)
        );

        CREATE INDEX IF NOT EXISTS ix_blocklist_type ON blocklist(type);
        CREATE INDEX IF NOT EXISTS ix_cache_expires ON scan_cache(expires_utc);
        """;
}

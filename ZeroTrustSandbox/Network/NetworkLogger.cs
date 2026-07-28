using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Network;

/// <summary>
/// Thread-safe recorder of all HTTP(S) traffic observed for a session. Entries
/// are surfaced to the UI in real time and can be exported to JSON for incident
/// response.
/// </summary>
public sealed class NetworkLogger
{
    private readonly ConcurrentQueue<NetworkLogEntry> _entries = new();

    public event EventHandler<NetworkLogEntry>? EntryLogged;

    public int Count => _entries.Count;

    public long TotalBytes { get; private set; }

    public int BlockedCount { get; private set; }

    public NetworkLogEntry LogRequest(string method, string uri, string? resourceType)
    {
        var entry = new NetworkLogEntry
        {
            Method = string.IsNullOrEmpty(method) ? "GET" : method,
            Uri = uri,
            ResourceType = resourceType
        };
        _entries.Enqueue(entry);
        EntryLogged?.Invoke(this, entry);
        return entry;
    }

    public void CompleteRequest(NetworkLogEntry entry, int statusCode, long bytes)
    {
        ArgumentNullException.ThrowIfNull(entry);
        entry.StatusCode = statusCode;
        entry.BytesReceived = bytes;
        TotalBytes += bytes;
    }

    public NetworkLogEntry LogBlocked(string method, string uri, string reason)
    {
        var entry = new NetworkLogEntry
        {
            Method = string.IsNullOrEmpty(method) ? "GET" : method,
            Uri = uri,
            Blocked = true,
            BlockReason = reason
        };
        _entries.Enqueue(entry);
        BlockedCount++;
        EntryLogged?.Invoke(this, entry);
        return entry;
    }

    public IReadOnlyList<NetworkLogEntry> Snapshot() => _entries.ToArray();

    /// <summary>Exports the full network log to a JSON file. Returns the path.</summary>
    public async Task<string> ExportJsonAsync(string directory, Guid sessionId, CancellationToken ct = default)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"network-{sessionId:N}.json");
        var options = new JsonSerializerOptions { WriteIndented = true };
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, Snapshot(), options, ct).ConfigureAwait(false);
        return path;
    }

    public void Clear()
    {
        _entries.Clear();
        TotalBytes = 0;
        BlockedCount = 0;
    }
}

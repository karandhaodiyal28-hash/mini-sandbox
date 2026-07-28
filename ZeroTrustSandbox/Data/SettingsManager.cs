using System.IO;
using Newtonsoft.Json;
using ZeroTrustSandbox.Common;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Data;

/// <summary>
/// Loads and persists <see cref="AppSettings"/> as JSON in %AppData%. The
/// VirusTotal API key is never stored here; it lives DPAPI-encrypted via
/// <c>KeyProtector</c>.
/// </summary>
public sealed class SettingsManager
{
    private readonly string _path;
    private readonly object _gate = new();

    public AppSettings Current { get; private set; } = new();

    public SettingsManager(string? path = null) => _path = path ?? AppPaths.SettingsFile;

    public async Task LoadAsync(CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(_path))
            {
                Current = new AppSettings();
                await SaveAsync(Current, ct).ConfigureAwait(false);
                return;
            }

            var json = await File.ReadAllTextAsync(_path, ct).ConfigureAwait(false);
            var loaded = JsonConvert.DeserializeObject<AppSettings>(json);
            Current = loaded ?? new AppSettings();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Corrupt or unreadable settings must never crash the app.
            Current = new AppSettings();
        }
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        string json;
        lock (_gate)
        {
            Current = settings;
            json = JsonConvert.SerializeObject(settings, Formatting.Indented);
        }

        // Atomic write: temp then move, so a crash mid-write can't corrupt.
        var tmp = _path + ".tmp";
        await File.WriteAllTextAsync(tmp, json, ct).ConfigureAwait(false);
        File.Move(tmp, _path, overwrite: true);
    }
}

using System.Net.Http;
using Microsoft.Extensions.Logging;
using ZeroTrustSandbox.Data;
using ZeroTrustSandbox.Models;
using ZeroTrustSandbox.Security;

namespace ZeroTrustSandbox.ViewModels;

/// <summary>View model for the settings window (API keys, toggles, quota).</summary>
public sealed class SettingsViewModel : ViewModelBase
{
    private readonly KeyProtector _keys;
    private readonly SettingsManager _settingsManager;
    private readonly CacheManager _cache;
    private readonly HttpClient _http;
    private readonly ILogger<SettingsViewModel> _log;

    public SettingsViewModel(
        KeyProtector keys,
        SettingsManager settingsManager,
        CacheManager cache,
        HttpClient http,
        ILogger<SettingsViewModel> log)
    {
        _keys = keys;
        _settingsManager = settingsManager;
        _cache = cache;
        _http = http;
        _log = log;

        Settings = _settingsManager.Current.Clone();
        _hasKey = _keys.HasKey;

        SaveKeyCommand = new AsyncRelayCommand(p => SaveKeyAsync(p as string), _ => !IsWorking);
        RemoveKeyCommand = new RelayCommand(_ => RemoveKey(), _ => HasKey);
        SaveSettingsCommand = new AsyncRelayCommand(_ => SaveSettingsAsync());
        _ = RefreshQuotaAsync();
    }

    public AppSettings Settings { get; }

    private bool _hasKey;
    public bool HasKey { get => _hasKey; private set => SetProperty(ref _hasKey, value); }

    private bool _isWorking;
    public bool IsWorking { get => _isWorking; private set => SetProperty(ref _isWorking, value); }

    private string _keyStatus = string.Empty;
    public string KeyStatus { get => _keyStatus; private set => SetProperty(ref _keyStatus, value); }

    private string _quotaText = "Daily quota: —";
    public string QuotaText { get => _quotaText; private set => SetProperty(ref _quotaText, value); }

    public AsyncRelayCommand SaveKeyCommand { get; }
    public RelayCommand RemoveKeyCommand { get; }
    public AsyncRelayCommand SaveSettingsCommand { get; }

    private async Task SaveKeyAsync(string? key)
    {
        if (!KeyProtector.IsValidFormat(key))
        {
            KeyStatus = "❌ Invalid format — expected 64 hexadecimal characters.";
            return;
        }

        IsWorking = true;
        KeyStatus = "Validating against VirusTotal…";
        try
        {
            var valid = await TestKeyAsync(key!).ConfigureAwait(true);
            if (!valid)
            {
                KeyStatus = "❌ VirusTotal rejected this key.";
                return;
            }

            await _keys.SaveKeyAsync(key!).ConfigureAwait(true);
            Settings.ApiKeySetUtc = DateTimeOffset.UtcNow;
            await _settingsManager.SaveAsync(Settings).ConfigureAwait(true);
            HasKey = true;
            KeyStatus = "✅ Key validated and stored (DPAPI-encrypted).";
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Saving API key failed.");
            KeyStatus = $"❌ {ex.Message}";
        }
        finally
        {
            IsWorking = false;
        }
    }

    private async Task<bool> TestKeyAsync(string key)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var request = new HttpRequestMessage(HttpMethod.Get,
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8");
            request.Headers.TryAddWithoutValidation("x-apikey", key);
            using var response = await _http.SendAsync(request, cts.Token).ConfigureAwait(true);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // Network problems shouldn't block saving a well-formed key.
            return true;
        }
    }

    private void RemoveKey()
    {
        _keys.RemoveKey();
        HasKey = false;
        KeyStatus = "Key removed and securely deleted.";
    }

    private async Task SaveSettingsAsync()
    {
        await _settingsManager.SaveAsync(Settings).ConfigureAwait(true);
        await RefreshQuotaAsync().ConfigureAwait(true);
    }

    private async Task RefreshQuotaAsync()
    {
        try
        {
            var used = await _cache.GetDailyUsageAsync().ConfigureAwait(true);
            QuotaText = $"VirusTotal today: {used}/{Settings.VtRequestsPerDay} requests used.";
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Quota refresh failed.");
        }
    }
}

using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using ZeroTrustSandbox.Common;
using ZeroTrustSandbox.Data;
using ZeroTrustSandbox.Models;
using ZeroTrustSandbox.Network;
using ZeroTrustSandbox.Security;

namespace ZeroTrustSandbox.Core;

/// <summary>
/// Owns the lifecycle of an isolated WebView2 preview session: ephemeral
/// (InPrivate) profile, randomized fingerprint re-applied per session, per-request
/// network logging and blocking, popup/download suppression, and teardown that
/// clears all browsing data. The throw-away profile directory is securely wiped
/// when the engine is disposed at app shutdown.
/// </summary>
public sealed class SandboxEngine : IAsyncDisposable
{
    private readonly SettingsManager _settings;
    private readonly BlocklistManager _blocklist;
    private readonly NetworkLogger _network;
    private readonly ProcessGuard _guard;
    private readonly ProcessIsolation _isolation;
    private readonly ILogger<SandboxEngine> _log;

    private WebView2? _view;
    private string? _profileDir;
    private string? _spoofScriptId;

    public SessionInfo? Current { get; private set; }

    public event EventHandler<NetworkLogEntry>? RequestBlocked;

    /// <summary>Raised when the active page URL changes (keeps the address bar in sync).</summary>
    public event EventHandler<string>? AddressChanged;

    /// <summary>Raised when back/forward availability changes.</summary>
    public event EventHandler? NavigationStateChanged;

    public SandboxEngine(
        SettingsManager settings,
        BlocklistManager blocklist,
        NetworkLogger network,
        ProcessGuard guard,
        ProcessIsolation isolation,
        ILogger<SandboxEngine> log)
    {
        _settings = settings;
        _blocklist = blocklist;
        _network = network;
        _guard = guard;
        _isolation = isolation;
        _log = log;
    }

    /// <summary>
    /// Prepares the WebView2 control for a fresh isolated session. The control is
    /// initialized once (InPrivate) and reused; each subsequent session clears all
    /// browsing data and re-applies a new randomized fingerprint. UI thread only.
    /// </summary>
    public async Task<SessionInfo> StartSessionAsync(WebView2 view, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(view);

        var cfg = _settings.Current;
        var session = new SessionInfo { Fingerprint = FingerprintGenerator.Create() };

        if (_view is null || _view.CoreWebView2 is null)
        {
            await InitializeControlAsync(view, cfg, session.Fingerprint).ConfigureAwait(true);
        }
        else
        {
            await ClearAsync(_view.CoreWebView2).ConfigureAwait(true);
            Harden(_view.CoreWebView2, session.Fingerprint);
        }

        Current = session;
        await ApplyFingerprintScriptAsync(_view!.CoreWebView2!, session).ConfigureAwait(true);
        _log.LogInformation("Sandbox session {Id} started.", session.Id);
        return session;
    }

    private async Task InitializeControlAsync(WebView2 view, AppSettings cfg, BrowserFingerprint fingerprint)
    {
        _profileDir = AppPaths.NewEphemeralProfileDir();
        _isolation.CreateJob(cfg.MaxSessionMemoryMb);

        var options = new CoreWebView2EnvironmentOptions
        {
            AdditionalBrowserArguments = "--no-first-run --disable-background-networking --disable-sync --disable-features=Translate"
        };
        var environment = await CoreWebView2Environment.CreateAsync(null, _profileDir, options).ConfigureAwait(true);

        CoreWebView2ControllerOptions? controllerOptions = null;
        try
        {
            controllerOptions = environment.CreateCoreWebView2ControllerOptions();
            controllerOptions.IsInPrivateModeEnabled = true;
        }
        catch (NotImplementedException)
        {
            controllerOptions = null; // older runtime; profile-dir wipe still applies
        }

        if (controllerOptions is not null)
        {
            await view.EnsureCoreWebView2Async(environment, controllerOptions).ConfigureAwait(true);
        }
        else
        {
            await view.EnsureCoreWebView2Async(environment).ConfigureAwait(true);
        }

        var core = view.CoreWebView2;
        Harden(core, fingerprint);
        WireEvents(core);

        _view = view;
        _guard.Start();
    }

    private void Harden(CoreWebView2 core, BrowserFingerprint fp)
    {
        var s = core.Settings;
        s.AreDevToolsEnabled = false;
        s.AreDefaultContextMenusEnabled = false;
        s.IsStatusBarEnabled = false;
        s.AreBrowserAcceleratorKeysEnabled = false;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;

        if (_settings.Current.RandomizeFingerprint)
        {
            try
            {
                s.UserAgent = fp.UserAgent;
            }
            catch (NotImplementedException)
            {
                // UserAgent setter unavailable on older runtime; ignore.
            }
        }
    }

    private void WireEvents(CoreWebView2 core)
    {
        core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
        core.WebResourceRequested += (_, e) => OnWebResourceRequested(core, e);

        // Block popups / new windows.
        core.NewWindowRequested += (_, e) => e.Handled = true;

        // Never allow silent disk downloads from the sandbox.
        core.DownloadStarting += (_, e) =>
        {
            e.Cancel = true;
            _network.LogBlocked("GET", e.DownloadOperation.Uri, "Download blocked (RAM-only policy)");
            if (Current is not null)
            {
                Current.RequestsBlocked++;
            }
        };

        // Keep the address bar + nav buttons in sync with in-page navigation.
        core.SourceChanged += (_, _) => AddressChanged?.Invoke(this, core.Source);
        core.HistoryChanged += (_, _) => NavigationStateChanged?.Invoke(this, EventArgs.Empty);
    }

    private async Task ApplyFingerprintScriptAsync(CoreWebView2 core, SessionInfo session)
    {
        if (!_settings.Current.RandomizeFingerprint)
        {
            return;
        }

        if (_spoofScriptId is not null)
        {
            try
            {
                core.RemoveScriptToExecuteOnDocumentCreated(_spoofScriptId);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                // previous script already gone
            }
        }

        var script = FingerprintGenerator.BuildSpoofScript(session.Fingerprint);
        _spoofScriptId = await core.AddScriptToExecuteOnDocumentCreatedAsync(script).ConfigureAwait(true);
    }

    private void OnWebResourceRequested(CoreWebView2 core, CoreWebView2WebResourceRequestedEventArgs e)
    {
        var uri = e.Request.Uri;
        var cfg = _settings.Current;
        var host = Uri.TryCreate(uri, UriKind.Absolute, out var u) ? u.Host : null;

        var blockReason = Evaluate(uri, host, cfg);
        if (blockReason is not null)
        {
            e.Response = core.Environment.CreateWebResourceResponse(null, 403, "Blocked by ZeroTrustSandbox", "Content-Type: text/plain");
            var entry = _network.LogBlocked(e.Request.Method, uri, blockReason);
            if (Current is not null)
            {
                Current.RequestsBlocked++;
                Current.Network.Add(entry);
            }
            RequestBlocked?.Invoke(this, entry);
            return;
        }

        var logged = _network.LogRequest(e.Request.Method, uri, e.ResourceContext.ToString());
        Current?.Network.Add(logged);
    }

    private string? Evaluate(string uri, string? host, AppSettings cfg)
    {
        if (host is not null && _blocklist.IsHostBlocked(host))
        {
            return "Host on blocklist";
        }
        if (_blocklist.IsUrlBlocked(uri))
        {
            return "URL matched blocklist pattern";
        }
        if (cfg.NetworkIsolationMode && Current?.Target is { } target &&
            Uri.TryCreate(target, UriKind.Absolute, out var main) && host is not null &&
            !host.EndsWith(main.Host, StringComparison.OrdinalIgnoreCase))
        {
            return "Network isolation: off-origin request blocked";
        }
        return null;
    }

    public async Task NavigateAsync(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        if (_view?.CoreWebView2 is null || Current is null)
        {
            throw new InvalidOperationException("No active sandbox session.");
        }
        Current.Target = url;
        Current.Kind = TargetKind.Url;
        _view.CoreWebView2.Navigate(url);
        await Task.CompletedTask.ConfigureAwait(true);
    }

    // ---- Browser navigation controls -----------------------------------

    public bool CanGoBack => _view?.CoreWebView2?.CanGoBack ?? false;
    public bool CanGoForward => _view?.CoreWebView2?.CanGoForward ?? false;

    public void GoBack()
    {
        if (_view?.CoreWebView2 is { CanGoBack: true } core)
        {
            core.GoBack();
        }
    }

    public void GoForward()
    {
        if (_view?.CoreWebView2 is { CanGoForward: true } core)
        {
            core.GoForward();
        }
    }

    public void Reload() => _view?.CoreWebView2?.Reload();

    public void StopNavigation() => _view?.CoreWebView2?.Stop();

    /// <summary>Renders locally reconstructed (disarmed) HTML content.</summary>
    public void NavigateToHtml(string html)
    {
        ArgumentNullException.ThrowIfNull(html);
        _view?.CoreWebView2?.NavigateToString(html);
    }

    /// <summary>
    /// Tears the session down: clears all browsing data and returns the control to
    /// a blank page. The control itself is preserved for the next session.
    /// </summary>
    public async Task DestroySessionAsync()
    {
        if (_view?.CoreWebView2 is { } core)
        {
            await ClearAsync(core).ConfigureAwait(true);
        }
        Current = null;
        _network.Clear();
    }

    private async Task ClearAsync(CoreWebView2 core)
    {
        try
        {
            await core.Profile.ClearBrowsingDataAsync().ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is NotImplementedException or InvalidOperationException)
        {
            _log.LogDebug(ex, "ClearBrowsingDataAsync unavailable.");
        }

        try
        {
            core.Navigate("about:blank");
        }
        catch (InvalidOperationException)
        {
            // control not ready
        }
    }

    private void WipeProfile()
    {
        if (_profileDir is null || !Directory.Exists(_profileDir))
        {
            _profileDir = null;
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(_profileDir, "*", SearchOption.AllDirectories))
            {
                SecureDelete.Overwrite(file, passes: 1);
            }
            Directory.Delete(_profileDir, recursive: true);
        }
        catch (IOException ex)
        {
            _log.LogDebug(ex, "Profile directory wipe deferred (locked).");
        }
        finally
        {
            _profileDir = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DestroySessionAsync().ConfigureAwait(true);

        if (_view is not null)
        {
            try
            {
                _view.Dispose();
            }
            catch (InvalidOperationException)
            {
                // already torn down
            }
            _view = null;
        }

        WipeProfile();
        _isolation.Dispose();
    }
}

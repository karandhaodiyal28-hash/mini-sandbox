using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Extensions.Logging;
using ZeroTrustSandbox.CDR;
using ZeroTrustSandbox.Core;
using ZeroTrustSandbox.Models;
using ZeroTrustSandbox.Network;
using ZeroTrustSandbox.Security;

namespace ZeroTrustSandbox.ViewModels;

/// <summary>
/// Abstraction the View implements so the view model can drive the WebView2
/// surface without referencing WPF WebView2 types directly.
/// </summary>
public interface IPreviewSurface
{
    Task StartAsync(CancellationToken ct);
    Task NavigateAsync(string url);
    void NavigateHtml(string html);
    Task DestroyAsync();
}

/// <summary>Primary view model for the main window.</summary>
public sealed class MainViewModel : ViewModelBase
{
    private readonly ScanOrchestrator _orchestrator;
    private readonly UrlResolver _urlResolver;
    private readonly SandboxEngine _engine;
    private readonly MemoryManager _memory;
    private readonly ImageDisarmer _imageDisarmer;
    private readonly PdfDisarmer _pdfDisarmer;
    private readonly OfficeDisarmer _officeDisarmer;
    private readonly NetworkLogger _network;
    private readonly ILogger<MainViewModel> _log;
    private readonly DispatcherTimer _timer;

    private CancellationTokenSource? _scanCts;

    public MainViewModel(
        ScanOrchestrator orchestrator,
        UrlResolver urlResolver,
        SandboxEngine engine,
        MemoryManager memory,
        ImageDisarmer imageDisarmer,
        PdfDisarmer pdfDisarmer,
        OfficeDisarmer officeDisarmer,
        NetworkLogger network,
        ILogger<MainViewModel> log)
    {
        _orchestrator = orchestrator;
        _urlResolver = urlResolver;
        _engine = engine;
        _memory = memory;
        _imageDisarmer = imageDisarmer;
        _pdfDisarmer = pdfDisarmer;
        _officeDisarmer = officeDisarmer;
        _network = network;
        _log = log;

        PreviewUrlCommand = new AsyncRelayCommand(_ => PreviewUrlAsync(), _ => !IsBusy && !string.IsNullOrWhiteSpace(AddressText));
        ForceDestroyCommand = new AsyncRelayCommand(_ => ForceDestroyAsync(), _ => SessionActive);
        BackCommand = new RelayCommand(_ => _engine.GoBack(), _ => _engine.CanGoBack);
        ForwardCommand = new RelayCommand(_ => _engine.GoForward(), _ => _engine.CanGoForward);
        ReloadCommand = new RelayCommand(_ => _engine.Reload(), _ => SessionActive);

        _network.EntryLogged += (_, entry) => OnUi(() => Network.Insert(0, entry));
        _engine.RequestBlocked += (_, entry) => OnUi(() => StatusDetail = $"Blocked: {entry.Uri}");

        // Keep the address bar + nav buttons in sync with in-page browsing.
        _engine.AddressChanged += (_, url) => OnUi(() =>
        {
            if (url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                AddressText = url;
            }
            CommandManager.InvalidateRequerySuggested();
        });
        _engine.NavigationStateChanged += (_, _) => OnUi(CommandManager.InvalidateRequerySuggested);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => OnPropertyChanged(nameof(SessionTimerText));
    }

    public IPreviewSurface? Surface { get; set; }

    public ObservableCollection<ThreatVerdict> Findings { get; } = new();
    public ObservableCollection<NetworkLogEntry> Network { get; } = new();

    private string _addressText = string.Empty;
    public string AddressText { get => _addressText; set => SetProperty(ref _addressText, value); }

    private bool _isBusy;
    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }

    private bool _sessionActive;
    public bool SessionActive
    {
        get => _sessionActive;
        private set { if (SetProperty(ref _sessionActive, value)) { OnPropertyChanged(nameof(SessionTimerText)); } }
    }

    private ThreatLevel _level = ThreatLevel.Unknown;
    public ThreatLevel Level
    {
        get => _level;
        private set { if (SetProperty(ref _level, value)) { OnPropertyChanged(nameof(StatusBrushKey)); OnPropertyChanged(nameof(StatusText)); } }
    }

    private int _riskScore;
    public int RiskScore { get => _riskScore; private set => SetProperty(ref _riskScore, value); }

    private string _statusDetail = "Enter a URL and click Preview to open it inside the sandbox.";
    public string StatusDetail { get => _statusDetail; set => SetProperty(ref _statusDetail, value); }

    public string StatusText => Level switch
    {
        ThreatLevel.Safe => "SAFE",
        ThreatLevel.Suspicious => "SUSPICIOUS",
        ThreatLevel.Malicious => "MALICIOUS",
        _ => "UNSCANNED"
    };

    public string StatusBrushKey => Level switch
    {
        ThreatLevel.Safe => "SafeBrush",
        ThreatLevel.Suspicious => "WarnBrush",
        ThreatLevel.Malicious => "DangerBrush",
        _ => "UnknownBrush"
    };

    public string SessionTimerText => SessionActive && _engine.Current is { } s
        ? $"Session active: {s.Elapsed:hh\\:mm\\:ss}"
        : "No active session";

    public AsyncRelayCommand PreviewUrlCommand { get; }
    public AsyncRelayCommand ForceDestroyCommand { get; }
    public RelayCommand BackCommand { get; }
    public RelayCommand ForwardCommand { get; }
    public RelayCommand ReloadCommand { get; }

    public async Task PreviewUrlAsync()
    {
        if (Surface is null)
        {
            return;
        }

        IsBusy = true;
        Findings.Clear();
        Network.Clear();
        _network.Clear();
        StatusDetail = "Resolving and scanning URL…";

        _scanCts?.Cancel();
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;

        try
        {
            var resolved = await _urlResolver.ResolveAsync(AddressText.Trim(), ct).ConfigureAwait(true);
            if (resolved.RedirectChain.Count > 1)
            {
                StatusDetail = $"Un-shortened to {resolved.Sanitized}";
            }

            var host = resolved.Host ?? string.Empty;
            var result = await _orchestrator.ScanUrlAsync(resolved.Sanitized, host, ct).ConfigureAwait(true);
            ApplyResult(result);

            if (result.Level == ThreatLevel.Malicious)
            {
                StatusDetail = "⚠ Malicious indicators detected. Opening in hardened isolation.";
            }

            await Surface.StartAsync(ct).ConfigureAwait(true);
            await Surface.NavigateAsync(resolved.Sanitized).ConfigureAwait(true);
            SessionActive = true;
            _timer.Start();
        }
        catch (OperationCanceledException)
        {
            StatusDetail = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Preview failed.");
            StatusDetail = $"Preview failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Scans and previews a local file through the CDR pipeline.</summary>
    public async Task PreviewFileAsync(string path)
    {
        if (Surface is null || string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        IsBusy = true;
        Findings.Clear();
        StatusDetail = $"Scanning {Path.GetFileName(path)}…";
        _scanCts?.Cancel();
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;

        try
        {
            using var buffer = await _memory.ReadFileAsync(path, ct).ConfigureAwait(true);
            var result = await _orchestrator.ScanFileAsync(buffer, Path.GetFileName(path), ct).ConfigureAwait(true);
            ApplyResult(result);

            var ext = Path.GetExtension(path).ToLowerInvariant();
            var disarm = Disarm(ext, buffer, Path.GetFileName(path));

            await Surface.StartAsync(ct).ConfigureAwait(true);
            if (disarm is { Success: true, Output: { } bytes })
            {
                StatusDetail = disarm.Message;
                RenderDisarmed(ext, bytes);
            }
            else
            {
                StatusDetail = disarm?.Message ?? "This file type has no CDR viewer; showing metadata only.";
                Surface.NavigateHtml(BuildFallbackHtml(result));
            }
            SessionActive = true;
            _timer.Start();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "File preview failed.");
            StatusDetail = $"File preview failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private DisarmResult? Disarm(string ext, EphemeralBuffer buffer, string name) => ext switch
    {
        ".pdf" => _pdfDisarmer.Disarm(buffer),
        ".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp" or ".webp" => _imageDisarmer.Disarm(buffer),
        ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm" => _officeDisarmer.Disarm(buffer, name),
        _ => null
    };

    private void RenderDisarmed(string ext, byte[] bytes)
    {
        if (Surface is null)
        {
            return;
        }
        if (ext is ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm")
        {
            Surface.NavigateHtml(System.Text.Encoding.UTF8.GetString(bytes));
        }
        else
        {
            var b64 = Convert.ToBase64String(bytes);
            var mime = ext == ".pdf" ? "application/pdf" : "image/png";
            var html = ext == ".pdf"
                ? $"<html><body style='margin:0'><embed src='data:{mime};base64,{b64}' width='100%' height='100%'/></body></html>"
                : $"<html><body style='margin:0;background:#1e1e1e;text-align:center'><img style='max-width:100%' src='data:{mime};base64,{b64}'/></body></html>";
            Surface.NavigateHtml(html);
        }
    }

    private static string BuildFallbackHtml(ScanResult result)
    {
        var rows = string.Join("", result.Verdicts.Select(v =>
            $"<tr><td>{System.Net.WebUtility.HtmlEncode(v.Source)}</td><td>{v.Level}</td><td>{System.Net.WebUtility.HtmlEncode(v.Summary)}</td></tr>"));
        return $"<html><body style='font-family:Segoe UI;background:#1e1e1e;color:#eee;padding:20px'>" +
               $"<h2>Scan report for {System.Net.WebUtility.HtmlEncode(result.Target)}</h2>" +
               $"<p>Risk score: {result.RiskScore}/100 — {result.Level}</p>" +
               $"<table border='1' cellpadding='6' style='border-collapse:collapse'>{rows}</table></body></html>";
    }

    private void ApplyResult(ScanResult result)
    {
        Level = result.Level;
        RiskScore = result.RiskScore;
        Findings.Clear();
        foreach (var v in result.Verdicts)
        {
            Findings.Add(v);
        }
    }

    public async Task ForceDestroyAsync()
    {
        _scanCts?.Cancel();
        _timer.Stop();
        if (Surface is not null)
        {
            await Surface.DestroyAsync().ConfigureAwait(true);
        }
        SessionActive = false;
        Level = ThreatLevel.Unknown;
        RiskScore = 0;
        Findings.Clear();
        Network.Clear();
        StatusDetail = "Session destroyed. All in-memory data wiped.";
    }

    private static void OnUi(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            dispatcher.Invoke(action);
        }
    }
}

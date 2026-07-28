using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using ZeroTrustSandbox.Common;
using ZeroTrustSandbox.Core;
using ZeroTrustSandbox.Data;
using ZeroTrustSandbox.Network;
using ZeroTrustSandbox.Security;
using ZeroTrustSandbox.Services;
using ZeroTrustSandbox.ViewModels;

namespace ZeroTrustSandbox;

/// <summary>Application entry point: composes the DI container and Serilog.</summary>
public partial class App : Application
{
    private IHost? _host;

    public IServiceProvider Services => _host?.Services
        ?? throw new InvalidOperationException("Host not initialized.");

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .WriteTo.File(System.IO.Path.Combine(AppPaths.LogsDir, "zts-.log"),
                rollingInterval: RollingInterval.Day, retainedFileCountLimit: 7,
                shared: true)
            .CreateLogger();

        // Never crash on an unhandled exception — log it and keep running.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Log.Error(args.ExceptionObject as Exception, "Unhandled non-UI exception.");
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            Log.Error(args.Exception, "Unobserved task exception.");
            args.SetObserved();
        };

        try
        {
            _host = BuildHost();
            await _host.StartAsync().ConfigureAwait(true);

            // One-time initialization of data + rules.
            await InitializeAsync().ConfigureAwait(true);

            var main = Services.GetRequiredService<MainWindow>();
            main.Show();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Fatal error during startup.");
            MessageBox.Show($"The application failed to start:\n\n{ex.Message}",
                "Zero Trust Sandbox", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    private async Task InitializeAsync()
    {
        var db = Services.GetRequiredService<DatabaseContext>();
        await db.InitializeAsync().ConfigureAwait(true);

        await Services.GetRequiredService<SettingsManager>().LoadAsync().ConfigureAwait(true);
        await Services.GetRequiredService<BlocklistManager>().LoadAsync().ConfigureAwait(true);

        var yara = Services.GetRequiredService<YaraScanner>();
        yara.LoadRulesFromDirectory(System.IO.Path.Combine(AppPaths.BundledResources, "YaraRules"));
        yara.LoadRulesFromDirectory(AppPaths.YaraRulesDir);
        Log.Information("Loaded {Count} YARA-lite rules.", yara.RuleCount);
    }

    private static IHost BuildHost()
    {
        return Host.CreateDefaultBuilder()
            .UseSerilog()
            .ConfigureServices(services =>
            {
                // Shared HttpClient (auto-redirect ON) for reputation feeds that
                // legitimately redirect (e.g. rdap.org 302 -> authoritative server).
                services.AddSingleton(_ =>
                {
                    var handler = new SocketsHttpHandler
                    {
                        AllowAutoRedirect = true,
                        MaxAutomaticRedirections = 5,
                        AutomaticDecompression = System.Net.DecompressionMethods.All,
                        ConnectTimeout = TimeSpan.FromSeconds(15),
                        PooledConnectionLifetime = TimeSpan.FromMinutes(5)
                    };
                    var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
                    http.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroTrustSandbox/1.0 (+https://github.com/)");
                    return http;
                });

                // Data
                services.AddSingleton(_ => new DatabaseContext());
                services.AddSingleton<CacheManager>();
                services.AddSingleton<SettingsManager>();
                services.AddSingleton<BlocklistManager>();

                // Security
                services.AddSingleton<KeyProtector>();
                services.AddSingleton(_ => new SlidingWindowRateLimiter(4, TimeSpan.FromMinutes(1)));
                services.AddSingleton<VirusTotalScanner>();
                services.AddSingleton<ThreatIntelligence>();
                services.AddSingleton<HibpClient>();
                services.AddSingleton<HeuristicAnalyzer>();
                services.AddSingleton<UrlHeuristicAnalyzer>();
                services.AddSingleton<YaraScanner>();
                services.AddSingleton(_ => TyposquatDetector.FromFile(
                    System.IO.Path.Combine(AppPaths.BundledResources, "Blocklists", "top-domains.txt")));
                services.AddSingleton<ClipboardGuard>();
                services.AddSingleton<ProcessGuard>();

                // Network
                // UrlResolver needs a NON-redirecting client so it can observe each
                // hop while un-shortening links in-memory.
                services.AddSingleton(sp =>
                {
                    var handler = new SocketsHttpHandler
                    {
                        AllowAutoRedirect = false,
                        ConnectTimeout = TimeSpan.FromSeconds(15),
                        PooledConnectionLifetime = TimeSpan.FromMinutes(5)
                    };
                    var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
                    http.DefaultRequestHeaders.UserAgent.ParseAdd("ZeroTrustSandbox/1.0");
                    return new UrlResolver(http, sp.GetRequiredService<ILogger<UrlResolver>>());
                });
                services.AddSingleton<DnsOverHttps>();
                services.AddSingleton<NetworkLogger>();

                // CDR
                services.AddSingleton<CDR.ImageDisarmer>();
                services.AddSingleton<CDR.PdfDisarmer>();
                services.AddSingleton<CDR.OfficeDisarmer>();

                // Core
                services.AddSingleton<ProcessIsolation>();
                services.AddSingleton(_ => new MemoryManager(100));
                services.AddSingleton<ScanOrchestrator>();
                services.AddSingleton<SandboxEngine>();

                // UI
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<MainWindow>();
                services.AddTransient<SettingsViewModel>();
                services.AddTransient<Views.SettingsWindow>();
            })
            .Build();
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error(e.Exception, "Unhandled UI exception.");
        MessageBox.Show($"An unexpected error occurred:\n\n{e.Exception.Message}",
            "Zero Trust Sandbox", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true; // keep the app alive
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        try
        {
            if (_host is not null)
            {
                await Services.GetRequiredService<SandboxEngine>().DisposeAsync().ConfigureAwait(true);
                await _host.StopAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(true);
                _host.Dispose();
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during shutdown.");
        }
        finally
        {
            Log.CloseAndFlush();
            base.OnExit(e);
        }
    }
}

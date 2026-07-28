using System.IO;

namespace ZeroTrustSandbox.Common;

/// <summary>
/// Central resolver for all filesystem locations the app uses. Everything is
/// derived from <see cref="Environment.SpecialFolder"/> so there are no
/// hardcoded absolute paths anywhere in the codebase.
/// </summary>
public static class AppPaths
{
    public const string AppFolderName = "ZeroTrustSandbox";

    /// <summary>%AppData%\ZeroTrustSandbox</summary>
    public static string Root { get; } = EnsureDir(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        AppFolderName));

    /// <summary>%LocalAppData%\ZeroTrustSandbox (larger, machine-local data).</summary>
    public static string LocalRoot { get; } = EnsureDir(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        AppFolderName));

    public static string DatabaseFile => Path.Combine(Root, "sandbox.db");
    public static string SettingsFile => Path.Combine(Root, "settings.json");

    /// <summary>DPAPI-encrypted API key blob.</summary>
    public static string ApiKeyFile => Path.Combine(Root, "user_key.dat");

    public static string LogsDir { get; } = EnsureDir(Path.Combine(Root, "logs"));
    public static string ReportsDir { get; } = EnsureDir(Path.Combine(Root, "reports"));
    public static string BlocklistsDir { get; } = EnsureDir(Path.Combine(Root, "blocklists"));
    public static string YaraRulesDir { get; } = EnsureDir(Path.Combine(Root, "yara"));

    /// <summary>Bundled read-only resources shipped next to the executable.</summary>
    public static string BundledResources => Path.Combine(AppContext.BaseDirectory, "Resources");

    /// <summary>
    /// A throw-away directory used only as a WebView2 user-data-folder root.
    /// WebView2 requires a folder path; we point it at a per-session GUID folder
    /// under %LocalAppData% and wipe it on session destroy.
    /// </summary>
    public static string NewEphemeralProfileDir()
        => EnsureDir(Path.Combine(LocalRoot, "profiles", Guid.NewGuid().ToString("N")));

    private static string EnsureDir(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
        }
        catch (IOException)
        {
            // Non-fatal: caller will surface a clearer error when it actually
            // tries to write. We never want path setup to crash startup.
        }
        return path;
    }
}

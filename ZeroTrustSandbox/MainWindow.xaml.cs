using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Win32;
using ZeroTrustSandbox.Core;
using ZeroTrustSandbox.ViewModels;
using ZeroTrustSandbox.Views;

namespace ZeroTrustSandbox;

/// <summary>
/// Main window. Implements <see cref="IPreviewSurface"/> so the view model can
/// drive the WebView2 control without depending on WebView2 types.
/// </summary>
public partial class MainWindow : Window, IPreviewSurface
{
    private readonly MainViewModel _vm;
    private readonly SandboxEngine _engine;
    private readonly IServiceProvider _services;

    public MainWindow(MainViewModel vm, SandboxEngine engine, IServiceProvider services)
    {
        _vm = vm;
        _engine = engine;
        _services = services;

        InitializeComponent();
        DataContext = _vm;
        _vm.Surface = this;
    }

    // ---- IPreviewSurface ------------------------------------------------

    public Task StartAsync(CancellationToken ct) => _engine.StartSessionAsync(Preview, ct);

    public Task NavigateAsync(string url) => _engine.NavigateAsync(url);

    public void NavigateHtml(string html) => _engine.NavigateToHtml(html);

    public Task DestroyAsync() => _engine.DestroySessionAsync();

    // ---- UI events ------------------------------------------------------

    private async void AddressBar_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && _vm.PreviewUrlCommand.CanExecute(null))
        {
            e.Handled = true;
            await _vm.PreviewUrlAsync().ConfigureAwait(true);
        }
    }

    private async void OpenFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select a file to preview safely",
            Filter = "Supported files|*.pdf;*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp;*.docx;*.xlsx;*.pptx;*.docm;*.xlsm;*.pptm|All files|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == true && File.Exists(dialog.FileName))
        {
            await _vm.PreviewFileAsync(dialog.FileName).ConfigureAwait(true);
        }
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var window = _services.GetRequiredService<SettingsWindow>();
        window.Owner = this;
        window.ShowDialog();
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        var window = new AboutWindow { Owner = this };
        window.ShowDialog();
    }

    private async void ForceDestroy_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(
            "Destroy the current sandbox session?\n\nAll in-memory data, cookies and cache will be securely wiped.",
            "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (confirm == MessageBoxResult.Yes)
        {
            await _vm.ForceDestroyAsync().ConfigureAwait(true);
        }
    }

    protected override async void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        try
        {
            await _engine.DestroySessionAsync().ConfigureAwait(true);
        }
        catch (Exception)
        {
            // best-effort teardown on close
        }
        base.OnClosing(e);
    }
}

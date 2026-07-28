using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;

namespace ZeroTrustSandbox.Views;

/// <summary>
/// Simple "About" dialog: app name, version, developer credit and a clickable
/// GitHub link for connecting and getting updates.
/// </summary>
public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = version is null ? "Version 1.0" : $"Version {version.Major}.{version.Minor}.{version.Build}";

        // Best-effort: show the app logo if it is bundled as a resource.
        try
        {
            LogoImage.Source = new BitmapImage(
                new Uri("pack://application:,,,/Resources/appicon.png", UriKind.Absolute));
        }
        catch (Exception)
        {
            // Logo is optional; ignore if the resource is unavailable.
        }
    }

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception)
        {
            MessageBox.Show(this, e.Uri.AbsoluteUri, "Open this link in your browser",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        e.Handled = true;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}

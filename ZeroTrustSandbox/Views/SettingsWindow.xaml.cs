using System.Windows;
using ZeroTrustSandbox.ViewModels;

namespace ZeroTrustSandbox.Views;

/// <summary>Settings dialog. The API key is passed via command parameter so it
/// is never bound to a persisted property.</summary>
public partial class SettingsWindow : Window
{
    private readonly SettingsViewModel _vm;

    public SettingsWindow(SettingsViewModel vm)
    {
        _vm = vm;
        InitializeComponent();
        DataContext = _vm;
    }

    private void SaveKey_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SaveKeyCommand.CanExecute(null))
        {
            _vm.SaveKeyCommand.Execute(ApiKeyBox.Password);
            ApiKeyBox.Clear();
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        // SaveSettingsCommand handles persistence; keep the window open.
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}

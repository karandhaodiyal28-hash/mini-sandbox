using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Converters;

/// <summary>Looks up an <see cref="Application"/> resource brush by its key string.</summary>
public sealed class ResourceKeyToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value as string ?? "UnknownBrush";
        return Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Maps a <see cref="ThreatLevel"/> to its badge brush.</summary>
public sealed class ThreatLevelToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value is ThreatLevel level
            ? level switch
            {
                ThreatLevel.Safe => "SafeBrush",
                ThreatLevel.Suspicious => "WarnBrush",
                ThreatLevel.Malicious => "DangerBrush",
                _ => "UnknownBrush"
            }
            : "UnknownBrush";
        return Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Inverts a boolean (used to enable controls when NOT busy).</summary>
public sealed class InverseBooleanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b && !b;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b && !b;
}

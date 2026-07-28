using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Have I Been Pwned integration. Password checks use the k-Anonymity model:
/// only the first 5 characters of the SHA-1 hash ever leave the machine, so the
/// full password (or even its full hash) is never transmitted.
/// </summary>
public sealed class HibpClient
{
    private const string Src = "HIBP";
    private readonly HttpClient _http;

    public HibpClient(HttpClient http) => _http = http;

    /// <summary>
    /// Returns how many times a password appears in breach corpora, or -1 when
    /// the service could not be reached. Never sends the password or full hash.
    /// </summary>
    public async Task<long> GetPasswordExposureCountAsync(string password, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = sha1[..5];
        var suffix = sha1[5..];

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));

            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.pwnedpasswords.com/range/{prefix}");
            request.Headers.Add("Add-Padding", "true"); // hide response size
            using var response = await _http.SendAsync(request, cts.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var body = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2 &&
                    string.Equals(parts[0], suffix, StringComparison.OrdinalIgnoreCase) &&
                    long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var count))
                {
                    return count;
                }
            }
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return -1;
        }
    }

    /// <summary>Wraps <see cref="GetPasswordExposureCountAsync"/> into a verdict.</summary>
    public async Task<ThreatVerdict> CheckPasswordAsync(string password, CancellationToken ct = default)
    {
        var count = await GetPasswordExposureCountAsync(password, ct).ConfigureAwait(false);
        return count switch
        {
            < 0 => ThreatVerdict.Info(Src, "Pwned Passwords service unavailable; skipped."),
            0 => ThreatVerdict.Safe(Src, "Password not found in known breaches."),
            < 100 => ThreatVerdict.Warn(Src, $"Password seen {count:N0} times in breaches — change it.", weight: 55),
            _ => ThreatVerdict.Danger(Src, $"Password seen {count:N0} times in breaches — highly compromised.", weight: 80)
        };
    }
}

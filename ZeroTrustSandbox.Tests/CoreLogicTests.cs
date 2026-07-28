using System.Diagnostics;
using System.Text;
using Xunit;
using ZeroTrustSandbox.Core;
using ZeroTrustSandbox.Models;
using ZeroTrustSandbox.Network;
using ZeroTrustSandbox.Security;
using ZeroTrustSandbox.Services;

namespace ZeroTrustSandbox.Tests;

public class UrlResolverTests
{
    [Fact]
    public void Sanitize_StripsTrackingParamsAndFragment()
    {
        var uri = new Uri("https://example.com/p?utm_source=news&id=5&fbclid=abc#section");
        var (sanitized, stripped) = UrlResolver.Sanitize(uri);

        Assert.Contains("id=5", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("utm_source", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("fbclid", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("#section", sanitized, StringComparison.Ordinal);
        Assert.Contains("utm_source", stripped);
        Assert.Contains("fbclid", stripped);
    }
}

public class YaraScannerTests
{
    [Fact]
    public void Scan_EicarString_Matches()
    {
        var scanner = new YaraScanner();
        scanner.LoadRules("""
            rule Eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: any of them }
            """);
        var data = Encoding.ASCII.GetBytes("prefix EICAR-STANDARD-ANTIVIRUS-TEST-FILE suffix");
        var results = scanner.Scan(data);
        Assert.Single(results);
        Assert.Equal(ThreatLevel.Malicious, results[0].Level);
    }

    [Fact]
    public void Scan_HexPattern_Matches()
    {
        var scanner = new YaraScanner();
        scanner.LoadRules("rule Mz { strings: $h = { 4D 5A ?? 00 } condition: any of them }");
        var data = new byte[] { 0x00, 0x4D, 0x5A, 0x90, 0x00 };
        Assert.Single(scanner.Scan(data));
    }

    [Fact]
    public void Scan_NonMatching_ReturnsEmpty()
    {
        var scanner = new YaraScanner();
        scanner.LoadRules("rule X { strings: $a = \"needle\" condition: any of them }");
        Assert.Empty(scanner.Scan(Encoding.ASCII.GetBytes("haystack only")));
    }
}

public class ScanAggregationTests
{
    [Fact]
    public void Aggregate_MaliciousVerdict_ProducesMaliciousLevel()
    {
        var result = new ScanResult { Target = "x", Kind = TargetKind.Url };
        result.Add(ThreatVerdict.Danger("VT", "bad", 90));
        ScanOrchestrator.Aggregate(result);

        Assert.Equal(ThreatLevel.Malicious, result.Level);
        Assert.True(result.RiskScore >= 70);
    }

    [Fact]
    public void Aggregate_OnlySafeVerdicts_ProducesSafeLevel()
    {
        var result = new ScanResult { Target = "x", Kind = TargetKind.Url };
        result.Add(ThreatVerdict.Safe("DoH", "resolved"));
        ScanOrchestrator.Aggregate(result);

        Assert.Equal(ThreatLevel.Safe, result.Level);
        Assert.True(result.RiskScore < 35);
    }

    [Fact]
    public void Aggregate_AccumulatedSuspicion_BecomesSuspicious()
    {
        var result = new ScanResult { Target = "x", Kind = TargetKind.Url };
        result.Add(ThreatVerdict.Warn("A", "new domain", 60));
        result.Add(ThreatVerdict.Warn("B", "no CT", 40));
        ScanOrchestrator.Aggregate(result);

        Assert.Equal(ThreatLevel.Suspicious, result.Level);
    }
}

public class VirusTotalHelperTests
{
    [Fact]
    public void Base64UrlNoPad_MatchesKnownVector()
        => Assert.Equal("aHR0cDovL3d3dy5nb29nbGUuY29tLw",
            VirusTotalScanner.Base64UrlNoPad("http://www.google.com/"));

    [Fact]
    public void Sha256Hex_MatchesKnownVector()
        => Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            VirusTotalScanner.Sha256Hex(Encoding.ASCII.GetBytes("abc")));
}

public class RateLimiterTests
{
    [Fact]
    public async Task WaitAsync_AllowsBurstThenThrottles()
    {
        var limiter = new SlidingWindowRateLimiter(2, TimeSpan.FromMilliseconds(400));
        await limiter.WaitAsync();
        await limiter.WaitAsync();

        var sw = Stopwatch.StartNew();
        await limiter.WaitAsync(); // must wait for the window to slide
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds >= 250, $"Expected throttling, waited {sw.ElapsedMilliseconds}ms.");
    }
}

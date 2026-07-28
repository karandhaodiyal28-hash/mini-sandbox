using System.Text;
using Xunit;
using ZeroTrustSandbox.Security;

namespace ZeroTrustSandbox.Tests;

public class HeuristicAnalyzerTests
{
    private readonly HeuristicAnalyzer _sut = new();

    [Fact]
    public void ShannonEntropy_UniformBuffer_IsZero()
    {
        var data = new byte[1024]; // all zeros
        Assert.Equal(0d, HeuristicAnalyzer.ShannonEntropy(data), 3);
    }

    [Fact]
    public void ShannonEntropy_AllDistinctBytes_IsEight()
    {
        var data = new byte[256];
        for (var i = 0; i < 256; i++)
        {
            data[i] = (byte)i;
        }
        Assert.Equal(8d, HeuristicAnalyzer.ShannonEntropy(data), 3);
    }

    [Fact]
    public void Analyze_MagicByteMismatch_IsFlagged()
    {
        // Claims to be a PNG but has no PNG signature.
        var data = Encoding.ASCII.GetBytes("not really a png at all");
        var verdicts = _sut.Analyze(data, "photo.png");
        Assert.Contains(verdicts, v => v.Summary.Contains("does NOT match", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyze_ExeDisguisedAsPdf_IsDanger()
    {
        var data = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03 };
        var verdicts = _sut.Analyze(data, "invoice.pdf");
        Assert.Contains(verdicts, v => v.Level == ZeroTrustSandbox.Models.ThreatLevel.Malicious);
    }

    [Fact]
    public void Analyze_HighEntropyCompressedType_NotFlaggedAsPacked()
    {
        var data = new byte[256];
        for (var i = 0; i < 256; i++)
        {
            data[i] = (byte)i; // entropy == 8.0
        }
        // A .png is compressed by design: high entropy must NOT raise a packed flag.
        var verdicts = _sut.Analyze(data, "image.png");
        Assert.DoesNotContain(verdicts, v => v.Summary.Contains("packed or encrypted", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyze_HighEntropyPlainType_IsFlaggedAsPacked()
    {
        var data = new byte[256];
        for (var i = 0; i < 256; i++)
        {
            data[i] = (byte)i; // entropy == 8.0
        }
        // A .bin is not expected to be compressed: high entropy IS suspicious.
        var verdicts = _sut.Analyze(data, "payload.bin");
        Assert.Contains(verdicts, v => v.Summary.Contains("packed or encrypted", StringComparison.Ordinal));
    }
}

public class TyposquatDetectorTests
{
    private readonly TyposquatDetector _sut = new(new[] { "google.com", "paypal.com", "microsoft.com" });

    [Theory]
    [InlineData("kitten", "sitting", 3)]
    [InlineData("flaw", "lawn", 2)]
    [InlineData("same", "same", 0)]
    public void Levenshtein_ComputesExpected(string a, string b, int expected)
        => Assert.Equal(expected, TyposquatDetector.Levenshtein(a, b));

    [Fact]
    public void Analyze_TyposquattedDomain_IsWarned()
    {
        var verdicts = _sut.Analyze("gooogle.com");
        Assert.Contains(verdicts, v => v.Summary.Contains("typo", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_LegitDomain_NoTypoWarning()
    {
        var verdicts = _sut.Analyze("google.com");
        Assert.DoesNotContain(verdicts, v => v.Summary.Contains("typo", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Skeletonize_MapsCyrillicToAscii()
        => Assert.Equal("paypal", TyposquatDetector.Skeletonize("\u0440\u0430ypal"));
}

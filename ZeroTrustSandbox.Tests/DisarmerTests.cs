using System.Text;
using Xunit;
using ZeroTrustSandbox.CDR;

namespace ZeroTrustSandbox.Tests;

public class PdfDisarmerTests
{
    private readonly PdfDisarmer _sut = new();

    [Fact]
    public void Disarm_NeutralizesJavaScriptToken()
    {
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj<</JavaScript 2 0 R>>endobj");
        var result = _sut.Disarm(pdf);

        Assert.True(result.Success);
        Assert.NotNull(result.Output);
        var text = Encoding.ASCII.GetString(result.Output!);
        Assert.DoesNotContain("/JavaScript", text, StringComparison.Ordinal);
        Assert.NotEmpty(result.RemovedItems);
    }

    [Fact]
    public void Disarm_PreservesByteLength()
    {
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7 /OpenAction /Launch trailer");
        var result = _sut.Disarm(pdf);
        Assert.Equal(pdf.Length, result.Output!.Length);
    }

    [Fact]
    public void Disarm_NonPdf_Fails()
    {
        var result = _sut.Disarm(Encoding.ASCII.GetBytes("hello world"));
        Assert.False(result.Success);
    }

    [Fact]
    public void Disarm_DoesNotCorruptSimilarNames()
    {
        // "/JStroke" contains the "/JS" token but is a different name; the
        // name-boundary guard must leave it intact while still neutralizing /Launch.
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7 /JStroke 5 /Launch trailer");
        var result = _sut.Disarm(pdf);
        var text = Encoding.ASCII.GetString(result.Output!);
        Assert.Contains("/JStroke", text, StringComparison.Ordinal);
        Assert.DoesNotContain("/Launch", text, StringComparison.Ordinal);
    }
}

public class ImageDisarmerTests
{
    private readonly ImageDisarmer _sut = new();

    // Minimal valid 1x1 PNG.
    private static readonly byte[] OnePixelPng = Convert.FromBase64String(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");

    [Fact]
    public void Disarm_ValidPng_ReEncodes()
    {
        var result = _sut.Disarm(OnePixelPng);
        Assert.True(result.Success, result.Message);
        Assert.NotNull(result.Output);
        // Re-encoded output is itself a PNG.
        Assert.Equal(0x89, result.Output![0]);
    }

    [Fact]
    public void Disarm_Garbage_Fails()
    {
        var result = _sut.Disarm(Encoding.ASCII.GetBytes("this is not an image"));
        Assert.False(result.Success);
    }

    [Fact]
    public void Disarm_Empty_Fails()
        => Assert.False(_sut.Disarm(ReadOnlySpan<byte>.Empty).Success);
}

public class OfficeDisarmerTests
{
    private readonly OfficeDisarmer _sut = new();

    [Fact]
    public void Disarm_NonZip_Fails()
    {
        var result = _sut.Disarm(Encoding.ASCII.GetBytes("not a zip"), "fake.docx");
        Assert.False(result.Success);
    }
}

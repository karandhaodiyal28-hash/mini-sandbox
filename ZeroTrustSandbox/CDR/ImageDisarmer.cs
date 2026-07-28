using SkiaSharp;
using ZeroTrustSandbox.Core;

namespace ZeroTrustSandbox.CDR;

/// <summary>Outcome of a disarm operation.</summary>
public sealed class DisarmResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public IReadOnlyList<string> RemovedItems { get; init; } = Array.Empty<string>();

    /// <summary>The reconstructed, safe bytes (owned by the caller).</summary>
    public byte[]? Output { get; init; }

    public static DisarmResult Fail(string message) => new() { Success = false, Message = message };
}

/// <summary>
/// Re-encodes images through SkiaSharp to a clean PNG. Because we decode to raw
/// pixels and re-encode, all EXIF/XMP/IPTC metadata and any trailing/appended
/// payloads are dropped. Dimensions are validated first to prevent decompression
/// bombs / integer-overflow style attacks.
/// </summary>
public sealed class ImageDisarmer
{
    // Reject anything that would allocate more than ~256 MP of pixels.
    private const long MaxPixels = 256L * 1024 * 1024;
    private const int MaxDimension = 30000;

    public DisarmResult Disarm(EphemeralBuffer image)
    {
        ArgumentNullException.ThrowIfNull(image);
        return Disarm(image.Span);
    }

    public DisarmResult Disarm(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return DisarmResult.Fail("Empty image buffer.");
        }

        using var data = SKData.CreateCopy(bytes.ToArray());

        // Validate header dimensions BEFORE decoding all the pixels.
        using var codec = SKCodec.Create(data);
        if (codec is null)
        {
            return DisarmResult.Fail("Unrecognized or corrupt image format.");
        }

        var info = codec.Info;
        if (info.Width <= 0 || info.Height <= 0 || info.Width > MaxDimension || info.Height > MaxDimension)
        {
            return DisarmResult.Fail($"Image dimensions {info.Width}x{info.Height} are out of bounds.");
        }
        if ((long)info.Width * info.Height > MaxPixels)
        {
            return DisarmResult.Fail("Image is too large to safely decode (possible decompression bomb).");
        }

        // Decode to pixels then re-encode. FromEncodedData handles every pixel
        // format (incl. 1-bit / palette PNGs) that SKBitmap.Decode(codec) can miss.
        using var decoded = SKImage.FromEncodedData(data);
        if (decoded is null)
        {
            return DisarmResult.Fail("Failed to decode image pixels.");
        }

        using var reencoded = decoded.Encode(SKEncodedImageFormat.Png, 100);
        if (reencoded is null)
        {
            return DisarmResult.Fail("Failed to re-encode image.");
        }

        return new DisarmResult
        {
            Success = true,
            Message = $"Re-encoded {info.Width}x{info.Height} {codec.EncodedFormat} to clean PNG.",
            RemovedItems = ["EXIF", "XMP", "IPTC", "ICC/appended data"],
            Output = reencoded.ToArray()
        };
    }
}

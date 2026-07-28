using System.Text;
using ZeroTrustSandbox.Core;

namespace ZeroTrustSandbox.CDR;

/// <summary>
/// Disarms PDFs without native dependencies by neutralizing the object names
/// that enable active content. Each dangerous key (e.g. <c>/JavaScript</c>,
/// <c>/OpenAction</c>, <c>/Launch</c>, <c>/EmbeddedFile</c>) is overwritten
/// in-place with a same-length benign token so the cross-reference table's byte
/// offsets remain valid and the file still opens as an inert document.
/// </summary>
/// <remarks>
/// This is a structural mitigation, not a full re-render. For maximum assurance
/// the app also rasterizes the PDF to images in the viewer path; this pass
/// guarantees the raw bytes handed to any viewer no longer trigger scripts,
/// auto-actions, launches or embedded-file extraction.
///
/// Known limitation: tokens stored inside compressed object streams
/// (<c>/ObjStm</c> + <c>FlateDecode</c>) are not visible to a plaintext byte
/// scan, so this pass cannot neutralize them. The defence-in-depth here is that
/// the preview renderer (Chromium/PDFium) does not execute PDF JavaScript by
/// default; treat this pass as a hardening layer, not a guarantee.
/// </remarks>
public sealed class PdfDisarmer
{
    private static readonly string[] DangerousTokens =
    [
        "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch",
        "/EmbeddedFile", "/EmbeddedFiles", "/RichMedia", "/XFA",
        "/GoToR", "/GoToE", "/SubmitForm", "/ImportData"
    ];

    public DisarmResult Disarm(EphemeralBuffer pdf)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        return Disarm(pdf.ToArray());
    }

    public DisarmResult Disarm(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        if (bytes.Length < 5 || bytes[0] != '%' || bytes[1] != 'P' || bytes[2] != 'D' || bytes[3] != 'F')
        {
            return DisarmResult.Fail("Not a valid PDF (missing %PDF header).");
        }

        var work = (byte[])bytes.Clone();
        var removed = new List<string>();

        foreach (var token in DangerousTokens)
        {
            var pattern = Encoding.ASCII.GetBytes(token);
            var count = NeutralizeAll(work, pattern);
            if (count > 0)
            {
                removed.Add($"{token} ×{count}");
            }
        }

        return new DisarmResult
        {
            Success = true,
            Message = removed.Count == 0
                ? "No active-content tokens found; PDF passed through unchanged."
                : $"Neutralized {removed.Count} active-content construct(s).",
            RemovedItems = removed,
            Output = work
        };
    }

    /// <summary>
    /// Overwrites every occurrence of <paramref name="pattern"/> with a
    /// same-length token that begins with '/' followed by 'X's, keeping the PDF
    /// structurally intact. Returns the number of occurrences neutralized.
    /// </summary>
    private static int NeutralizeAll(byte[] data, byte[] pattern)
    {
        var count = 0;
        var limit = data.Length - pattern.Length;
        for (var i = 0; i <= limit; i++)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (!match)
            {
                continue;
            }

            // Only neutralize a COMPLETE PDF name token: the byte right after the
            // token must be a PDF delimiter/whitespace. Otherwise "/JS" would also
            // corrupt unrelated names such as "/JStroke".
            var end = i + pattern.Length;
            if (end < data.Length && !IsPdfDelimiter(data[end]))
            {
                continue;
            }

            // Keep the leading '/', blank the rest with 'X'.
            data[i] = (byte)'/';
            for (var j = 1; j < pattern.Length; j++)
            {
                data[i + j] = (byte)'X';
            }
            count++;
            i += pattern.Length - 1;
        }
        return count;
    }

    // PDF name/token delimiters (whitespace + the 8 delimiter chars + comment).
    private static bool IsPdfDelimiter(byte b) =>
        b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)'\f' or 0
          or (byte)'/' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']'
          or (byte)'(' or (byte)')' or (byte)'{' or (byte)'}' or (byte)'%';
}

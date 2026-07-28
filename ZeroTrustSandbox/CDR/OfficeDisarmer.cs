using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using ZeroTrustSandbox.Core;

namespace ZeroTrustSandbox.CDR;

/// <summary>
/// Disarms OOXML Office documents (DOCX/XLSX/PPTX and their macro-enabled
/// variants). It treats the package as the ZIP it is, drops every active/embedded
/// part (VBA macros, OLE objects, ActiveX, external links) and reconstructs the
/// visible text into a static, script-free HTML document for safe preview.
/// </summary>
public sealed partial class OfficeDisarmer
{
    private static readonly string[] DangerousEntryMarkers =
    [
        "vbaproject.bin", "/embeddings/", "/oleobject", "activex", "/macros/",
        "vbadata.xml", "/media/", // media re-embedded separately if needed
    ];

    // Decompression-bomb guards: a small OOXML (ZIP) can inflate to many GB.
    private const long MaxEntryBytes = 25L * 1024 * 1024;    // per-part decompressed cap
    private const int MaxTotalTextChars = 40 * 1024 * 1024;  // total extracted text cap
    private const int MaxEntries = 5000;                     // max parts to inspect

    public DisarmResult Disarm(EphemeralBuffer doc, string fileName)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return Disarm(doc.ToArray(), fileName);
    }

    public DisarmResult Disarm(byte[] bytes, string fileName)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        var removed = new List<string>();
        var text = new StringBuilder();

        try
        {
            using var input = new MemoryStream(bytes, writable: false);
            using var archive = new ZipArchive(input, ZipArchiveMode.Read);

            var entryCount = 0;
            foreach (var entry in archive.Entries)
            {
                if (++entryCount > MaxEntries)
                {
                    removed.Add("… (too many parts; remaining entries skipped)");
                    break;
                }

                var lower = entry.FullName.ToLowerInvariant();

                if (DangerousEntryMarkers.Any(m => lower.Contains(m, StringComparison.Ordinal)))
                {
                    removed.Add(entry.FullName);
                    continue; // dropped from reconstruction
                }

                // Extract visible text from the primary content parts only.
                var isContent = lower.EndsWith("word/document.xml", StringComparison.Ordinal)
                    || lower.Contains("ppt/slides/slide", StringComparison.Ordinal)
                    || lower.Contains("xl/sharedstrings.xml", StringComparison.Ordinal)
                    || lower.Contains("xl/worksheets/sheet", StringComparison.Ordinal);

                if (isContent && text.Length < MaxTotalTextChars)
                {
                    var xml = ReadCappedText(entry, MaxEntryBytes);
                    if (xml is null)
                    {
                        removed.Add($"oversized part skipped (decompression-bomb guard): {entry.FullName}");
                    }
                    else
                    {
                        text.Append(ExtractText(xml)).Append('\n');
                    }
                }

                // Any external relationship targets are reported.
                if (lower.EndsWith(".rels", StringComparison.Ordinal))
                {
                    var rels = ReadCappedText(entry, 4L * 1024 * 1024);
                    if (rels is not null && rels.Contains("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase))
                    {
                        removed.Add($"external links in {entry.FullName}");
                    }
                }
            }
        }
        catch (InvalidDataException)
        {
            return DisarmResult.Fail("File is not a valid OOXML (ZIP) document.");
        }

        var html = BuildHtml(fileName, text.ToString());
        return new DisarmResult
        {
            Success = true,
            Message = removed.Count == 0
                ? "No active content found; reconstructed as static HTML."
                : $"Stripped {removed.Count} active/embedded part(s); reconstructed as static HTML.",
            RemovedItems = removed,
            Output = Encoding.UTF8.GetBytes(html)
        };
    }

    private static string ExtractText(string xml)
    {
        // Insert spaces for paragraph/line breaks, then strip all tags.
        xml = ParagraphBreakRegex().Replace(xml, "\n");
        var noTags = TagRegex().Replace(xml, string.Empty);
        return WebUtility.HtmlDecode(noTags);
    }

    /// <summary>
    /// Reads a ZIP entry into a UTF-8 string but aborts (returns null) once the
    /// decompressed size exceeds <paramref name="cap"/> — this bounds the ACTUAL
    /// inflated bytes regardless of the (spoofable) declared entry length, so a
    /// zip/decompression bomb cannot exhaust memory.
    /// </summary>
    private static string? ReadCappedText(ZipArchiveEntry entry, long cap)
    {
        using var s = entry.Open();
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (ms.Length + read > cap)
            {
                return null;
            }
            ms.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static string BuildHtml(string fileName, string text)
    {
        var safeName = WebUtility.HtmlEncode(fileName);
        var body = WebUtility.HtmlEncode(text)
            .Replace("\n", "<br/>", StringComparison.Ordinal);

        return $$"""
            <!DOCTYPE html>
            <html lang="en"><head><meta charset="utf-8"/>
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';"/>
            <title>Disarmed: {{safeName}}</title>
            <style>
              body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#e0e0e0;margin:0;padding:24px;line-height:1.6}
              .banner{background:#2d2d30;border-left:4px solid #4CAF50;padding:12px 16px;margin-bottom:20px;border-radius:4px}
              .content{background:#252526;padding:20px;border-radius:6px;white-space:normal}
            </style></head>
            <body>
              <div class="banner">🛡️ This document was disarmed. Macros, OLE objects and external
              links were removed. Only static text is shown below.</div>
              <div class="content">{{body}}</div>
            </body></html>
            """;
    }

    [GeneratedRegex(@"</w:p>|</a:p>|<w:br\s*/>|</w:tr>", RegexOptions.IgnoreCase)]
    private static partial Regex ParagraphBreakRegex();

    [GeneratedRegex(@"<[^>]+>")]
    private static partial Regex TagRegex();
}

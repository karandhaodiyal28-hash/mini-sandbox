using System.IO;
using System.Security.Cryptography;

namespace ZeroTrustSandbox.Core;

/// <summary>
/// An in-memory byte buffer that is cryptographically wiped (random overwrite
/// then zero) before the backing array is released. Used for all untrusted
/// downloads so nothing sensitive is ever written to disk.
/// </summary>
public sealed class EphemeralBuffer : IDisposable
{
    private byte[]? _data;

    public EphemeralBuffer(byte[] data) => _data = data ?? throw new ArgumentNullException(nameof(data));

    public int Length => _data?.Length ?? 0;

    public ReadOnlySpan<byte> Span => _data is null
        ? ReadOnlySpan<byte>.Empty
        : _data.AsSpan();

    public byte[] ToArray()
    {
        ObjectDisposedException.ThrowIf(_data is null, this);
        return (byte[])_data.Clone();
    }

    public void Dispose()
    {
        if (_data is not null)
        {
            RandomNumberGenerator.Fill(_data);        // overwrite with random
            CryptographicOperations.ZeroMemory(_data); // then zero
            _data = null;
        }
    }
}

/// <summary>
/// Streams untrusted content into RAM only, enforcing a hard size cap so a
/// malicious server cannot exhaust memory. Never touches the disk.
/// </summary>
public sealed class MemoryManager
{
    private readonly int _maxBytes;

    public MemoryManager(int maxMegabytes = 100) => _maxBytes = Math.Max(1, maxMegabytes) * 1024 * 1024;

    /// <summary>Reads a stream into an <see cref="EphemeralBuffer"/>, capped at the limit.</summary>
    public async Task<EphemeralBuffer> ReadToMemoryAsync(Stream source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source);

        using var ms = new MemoryStream();
        var rent = new byte[81920];
        int read;
        while ((read = await source.ReadAsync(rent, ct).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + read > _maxBytes)
            {
                throw new InvalidOperationException($"Download exceeds the {_maxBytes / (1024 * 1024)}MB in-memory limit.");
            }
            ms.Write(rent, 0, read);
        }
        CryptographicOperations.ZeroMemory(rent);
        return new EphemeralBuffer(ms.ToArray());
    }

    /// <summary>Reads a local file fully into RAM (used for file-preview targets).</summary>
    public async Task<EphemeralBuffer> ReadFileAsync(string path, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var info = new FileInfo(path);
        if (info.Length > _maxBytes)
        {
            throw new InvalidOperationException($"File exceeds the {_maxBytes / (1024 * 1024)}MB in-memory limit.");
        }

        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        return await ReadToMemoryAsync(fs, ct).ConfigureAwait(false);
    }
}

using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Best-effort secure deletion of files using a DoD 5220.22-M style 3-pass
/// overwrite (zeros, ones, random) followed by truncation and unlink.
/// </summary>
/// <remarks>
/// On modern SSDs with wear-leveling, overwriting cannot guarantee physical
/// erasure of every prior copy. This is a defense-in-depth measure; the
/// primary protection in this app is that sensitive data stays in RAM only.
/// </remarks>
public static class SecureDelete
{
    public static void Overwrite(string path, int passes = 3)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var length = new FileInfo(path).Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[81920];
                for (var pass = 0; pass < Math.Max(1, passes); pass++)
                {
                    fs.Seek(0, SeekOrigin.Begin);
                    FillPass(buffer, pass);
                    long written = 0;
                    while (written < length)
                    {
                        if (pass == 2) // random pass
                        {
                            RandomNumberGenerator.Fill(buffer);
                        }
                        var toWrite = (int)Math.Min(buffer.Length, length - written);
                        fs.Write(buffer, 0, toWrite);
                        written += toWrite;
                    }
                    fs.Flush(flushToDisk: true);
                }
                fs.SetLength(0);
            }
            File.Delete(path);
        }
        catch (IOException)
        {
            // Fall back to a plain delete so we never leave the file behind.
            TryDelete(path);
        }
        catch (UnauthorizedAccessException)
        {
            TryDelete(path);
        }
    }

    private static void FillPass(byte[] buffer, int pass)
    {
        switch (pass)
        {
            case 0: Array.Clear(buffer); break;           // 0x00
            case 1: Array.Fill(buffer, (byte)0xFF); break; // 0xFF
            default: RandomNumberGenerator.Fill(buffer); break;
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

/// <summary>Helpers for working with <see cref="SecureString"/> safely.</summary>
public static class SecureStringExtensions
{
    /// <summary>
    /// Marshals the secret to a plain string, invokes <paramref name="use"/>,
    /// then attempts to clear the unmanaged copy. The managed string cannot be
    /// wiped, so keep the delegate body as short as possible.
    /// </summary>
    public static T Use<T>(this SecureString secure, Func<string, T> use)
    {
        ArgumentNullException.ThrowIfNull(secure);
        ArgumentNullException.ThrowIfNull(use);

        var ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
            var plain = Marshal.PtrToStringUni(ptr) ?? string.Empty;
            return use(plain);
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }
    }
}

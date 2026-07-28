using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using ZeroTrustSandbox.Common;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Protects the VirusTotal API key at rest using Windows DPAPI
/// (<see cref="DataProtectionScope.CurrentUser"/>). The plaintext key is only
/// ever materialized transiently inside a <see cref="SecureString"/> and the
/// backing byte arrays are zeroed immediately after use.
/// </summary>
public sealed class KeyProtector
{
    // Extra entropy bound to this app; not a secret by itself but raises the
    // bar for cross-app decryption of the blob.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ZeroTrustSandbox::vt-key::v1");

    private readonly string _path;

    public KeyProtector(string? path = null) => _path = path ?? AppPaths.ApiKeyFile;

    public bool HasKey => File.Exists(_path);

    /// <summary>Encrypts and stores the API key. Zeros the input buffer afterwards.</summary>
    public async Task SaveKeyAsync(string apiKey, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        var plain = Encoding.UTF8.GetBytes(apiKey);
        try
        {
            var cipher = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
            var tmp = _path + ".tmp";
            await File.WriteAllBytesAsync(tmp, cipher, ct).ConfigureAwait(false);
            File.Move(tmp, _path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>
    /// Decrypts the key into a <see cref="SecureString"/>. Returns null when no
    /// key is stored. The caller is responsible for disposing the result.
    /// </summary>
    public SecureString? LoadKeySecure()
    {
        if (!File.Exists(_path))
        {
            return null;
        }

        byte[]? cipher = null;
        byte[]? plain = null;
        try
        {
            cipher = File.ReadAllBytes(_path);
            plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
            var secure = new SecureString();
            foreach (var c in Encoding.UTF8.GetString(plain))
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }
        catch (CryptographicException)
        {
            // Blob was created by another user/machine or is corrupt.
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        finally
        {
            if (plain is not null)
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
    }

    /// <summary>Securely deletes the stored key (DoD-style 3-pass overwrite).</summary>
    public void RemoveKey()
    {
        if (!File.Exists(_path))
        {
            return;
        }
        SecureDelete.Overwrite(_path);
    }

    /// <summary>Validates a VirusTotal key format: 64 lowercase hex chars.</summary>
    public static bool IsValidFormat(string? key)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length != 64)
        {
            return false;
        }
        foreach (var c in key)
        {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex)
            {
                return false;
            }
        }
        return true;
    }
}

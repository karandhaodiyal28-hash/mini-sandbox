using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace ZeroTrustSandbox.Security;

/// <summary>
/// Enforces a one-way clipboard policy for the sandbox:
/// <list type="bullet">
/// <item>the sandbox may <b>read</b> the host clipboard only after explicit user
/// consent (<see cref="ReadHostClipboardWithConsent"/>);</item>
/// <item>the sandbox may never <b>write</b> to the host clipboard — there is
/// deliberately no write method exposed;</item>
/// <item>anything copied out of the sandbox is DPAPI-encrypted at the boundary.</item>
/// </list>
/// </summary>
public sealed class ClipboardGuard
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ZeroTrustSandbox::clipboard::v1");

    /// <summary>User-controlled master switch. Defaults to denying reads.</summary>
    public bool ReadConsentGranted { get; set; }

    /// <summary>
    /// Returns the host clipboard text only if the user has granted consent for
    /// this session; otherwise returns null. Must be called on the UI (STA) thread.
    /// </summary>
    public string? ReadHostClipboardWithConsent()
    {
        if (!ReadConsentGranted)
        {
            return null;
        }

        try
        {
            return Clipboard.ContainsText() ? Clipboard.GetText() : null;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Clipboard is locked by another process; treat as empty.
            return null;
        }
    }

    /// <summary>
    /// Encrypts data that originated inside the sandbox before it is ever handed
    /// to host-side code, so plaintext never lingers in shared memory.
    /// </summary>
    public static byte[] EncryptForBoundary(string data)
    {
        ArgumentNullException.ThrowIfNull(data);
        var plain = Encoding.UTF8.GetBytes(data);
        try
        {
            return ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static string DecryptFromBoundary(byte[] cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        var plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
        try
        {
            return Encoding.UTF8.GetString(plain);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}

using System.Security.Cryptography;
using System.Text;
using ZeroTrustSandbox.Models;

namespace ZeroTrustSandbox.Network;

/// <summary>
/// Generates a randomized <see cref="BrowserFingerprint"/> per session and the
/// JavaScript used to enforce it inside the isolated WebView2 renderer.
/// </summary>
public static class FingerprintGenerator
{
    private static readonly string[] UserAgents =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    ];

    private static readonly string[] Languages = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-CA,en;q=0.8", "en-AU,en;q=0.8"];
    private static readonly (int W, int H)[] Resolutions = [(1920, 1080), (1536, 864), (1440, 900), (1366, 768), (2560, 1440)];
    private static readonly string[] Timezones = ["UTC", "America/New_York", "Europe/London", "Europe/Berlin", "Asia/Tokyo"];
    private static readonly (string Vendor, string Renderer)[] WebGl =
    [
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ];

    public static BrowserFingerprint Create()
    {
        var res = Pick(Resolutions);
        var gl = Pick(WebGl);
        return new BrowserFingerprint
        {
            UserAgent = Pick(UserAgents),
            AcceptLanguage = Pick(Languages),
            ScreenWidth = res.W,
            ScreenHeight = res.H,
            ColorDepth = RandomNumberGenerator.GetInt32(0, 2) == 0 ? 24 : 30,
            Timezone = Pick(Timezones),
            WebGlVendor = gl.Vendor,
            WebGlRenderer = gl.Renderer
        };
    }

    /// <summary>
    /// Builds a script (for AddScriptToExecuteOnDocumentCreated) that overrides
    /// the fingerprintable surface: screen metrics, language, timezone, WebGL
    /// vendor/renderer and canvas readback noise.
    /// </summary>
    public static string BuildSpoofScript(BrowserFingerprint fp)
    {
        ArgumentNullException.ThrowIfNull(fp);
        // A per-session canvas noise seed derived from a random byte.
        var seed = RandomNumberGenerator.GetInt32(1, 251);

        var sb = new StringBuilder();
        sb.Append("(function(){try{");
        sb.Append($"Object.defineProperty(screen,'width',{{get:()=>{fp.ScreenWidth}}});");
        sb.Append($"Object.defineProperty(screen,'height',{{get:()=>{fp.ScreenHeight}}});");
        sb.Append($"Object.defineProperty(screen,'colorDepth',{{get:()=>{fp.ColorDepth}}});");
        sb.Append($"Object.defineProperty(navigator,'language',{{get:()=>'{fp.AcceptLanguage.Split(',')[0]}'}});");
        // Timezone
        sb.Append("var _DTF=Intl.DateTimeFormat;Intl.DateTimeFormat=function(...a){var o=new _DTF(...a);var ro=o.resolvedOptions.bind(o);o.resolvedOptions=function(){var r=ro();r.timeZone='")
          .Append(fp.Timezone).Append("';return r;};return o;};");
        // WebGL vendor/renderer
        sb.Append("var _gp=WebGLRenderingContext.prototype.getParameter;WebGLRenderingContext.prototype.getParameter=function(p){if(p===37445)return '")
          .Append(fp.WebGlVendor).Append("';if(p===37446)return '").Append(fp.WebGlRenderer).Append("';return _gp.call(this,p);};");
        // Canvas noise
        sb.Append("var _td=HTMLCanvasElement.prototype.toDataURL;HTMLCanvasElement.prototype.toDataURL=function(){var c=this.getContext('2d');if(c){var d=c.getImageData(0,0,this.width,this.height);for(var i=0;i<d.data.length;i+=97){d.data[i]=(d.data[i]+")
          .Append(seed).Append(")%256;}c.putImageData(d,0,0);}return _td.apply(this,arguments);};");
        // Block third-party-ish enumeration of plugins
        sb.Append("Object.defineProperty(navigator,'plugins',{get:()=>[]});");
        sb.Append("}catch(e){}})();");
        return sb.ToString();
    }

    private static T Pick<T>(T[] items) => items[RandomNumberGenerator.GetInt32(0, items.Length)];
}

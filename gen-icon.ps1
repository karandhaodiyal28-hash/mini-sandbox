# Generates Mini Sandbox app icon (appicon.png + multi-resolution appicon.ico)
# using GDI+ (System.Drawing). Developed for Karan Dhaodiyal.
Add-Type -AssemblyName System.Drawing

$resDir = Join-Path $PSScriptRoot 'ZeroTrustSandbox\Resources'
if (-not (Test-Path $resDir)) { New-Item -ItemType Directory -Path $resDir | Out-Null }

$S = 256
$bmp = New-Object System.Drawing.Bitmap($S, $S)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.Clear([System.Drawing.Color]::Transparent)

function RoundRect($x, $y, $w, $h, $r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

# --- rounded navy background with vertical gradient ---
$bgPath = RoundRect 8 8 240 240 46
$bgRect = New-Object System.Drawing.Rectangle(8, 8, 240, 240)
$bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($bgRect,
    [System.Drawing.Color]::FromArgb(255, 20, 34, 58),
    [System.Drawing.Color]::FromArgb(255, 9, 18, 33),
    [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
$g.FillPath($bgBrush, $bgPath)

# --- shield ---
$shield = New-Object System.Drawing.Drawing2D.GraphicsPath
$pts = @(
    (New-Object System.Drawing.PointF(128, 46)),
    (New-Object System.Drawing.PointF(198, 78)),
    (New-Object System.Drawing.PointF(198, 132)),
    (New-Object System.Drawing.PointF(128, 210)),
    (New-Object System.Drawing.PointF(58, 132)),
    (New-Object System.Drawing.PointF(58, 78))
)
$shield.AddPolygon([System.Drawing.PointF[]]$pts)
$shieldRect = New-Object System.Drawing.Rectangle(58, 46, 140, 164)
$shieldBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($shieldRect,
    [System.Drawing.Color]::FromArgb(255, 45, 212, 191),
    [System.Drawing.Color]::FromArgb(255, 13, 148, 136),
    [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal)
$g.FillPath($shieldBrush, $shield)

# --- inner "sandbox" box (isolation container) ---
$boxPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 240, 249, 255), 10)
$boxPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$box = RoundRect 100 104 56 46 8
$g.DrawPath($boxPen, $box)
# small inner dashed square implies "contained/isolated"
$dashPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(230, 240, 249, 255), 5)
$dashPen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
$g.DrawRectangle($dashPen, 115, 118, 26, 20)

$g.Dispose()

# --- save PNG ---
$pngPath = Join-Path $resDir 'appicon.png'
$bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Output "PNG  -> $pngPath"

# --- build multi-resolution ICO (PNG-compressed entries) ---
$sizes = 256, 128, 64, 48, 32, 24, 16
$blobs = @()
foreach ($sz in $sizes) {
    $rb = New-Object System.Drawing.Bitmap($sz, $sz)
    $rg = [System.Drawing.Graphics]::FromImage($rb)
    $rg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $rg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $rg.DrawImage($bmp, 0, 0, $sz, $sz)
    $rg.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $rb.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $blobs += , @{ Size = $sz; Bytes = $ms.ToArray() }
    $rb.Dispose()
}

$icoPath = Join-Path $resDir 'appicon.ico'
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([UInt16]0)                 # reserved
$bw.Write([UInt16]1)                 # type = icon
$bw.Write([UInt16]$blobs.Count)      # image count
$offset = 6 + (16 * $blobs.Count)
foreach ($b in $blobs) {
    $dim = if ($b.Size -ge 256) { 0 } else { $b.Size }
    $bw.Write([Byte]$dim)            # width
    $bw.Write([Byte]$dim)            # height
    $bw.Write([Byte]0)              # palette
    $bw.Write([Byte]0)              # reserved
    $bw.Write([UInt16]1)            # planes
    $bw.Write([UInt16]32)           # bpp
    $bw.Write([UInt32]$b.Bytes.Length)
    $bw.Write([UInt32]$offset)
    $offset += $b.Bytes.Length
}
foreach ($b in $blobs) { $bw.Write($b.Bytes) }
$bw.Flush(); $bw.Close(); $fs.Close()
$bmp.Dispose()
Write-Output "ICO  -> $icoPath ($($blobs.Count) sizes)"

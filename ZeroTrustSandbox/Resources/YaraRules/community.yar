/*
    Zero Trust Sandbox — bundled YARA-lite rules.

    These use the subset understood by the built-in pure-C# engine:
      - text strings ($x = "..."), optionally nocase / wide
      - hex strings  ($h = { DE AD BE EF ?? })
      - regex strings ($r = /.../)
      - conditions: "any of them", "all of them", "N of them",
        or boolean combinations of $ids joined by and/or.

    Add your own community rules to %AppData%\ZeroTrustSandbox\yara\.
*/

rule EICAR_Test_File
{
    meta:
        description = "Standard EICAR anti-malware test string"
        severity = "60"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        any of them
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell download-and-execute cradle"
        severity = "85"
    strings:
        $a = "powershell" nocase
        $b = "DownloadString" nocase
        $c = "IEX" nocase
        $d = "FromBase64String" nocase
    condition:
        2 of them
}

rule Office_Macro_AutoExec
{
    meta:
        description = "VBA auto-execution entry points"
        severity = "80"
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Shell(" nocase
        $d = "CreateObject" nocase
    condition:
        2 of them
}

rule Windows_PE_With_Injection_APIs
{
    meta:
        description = "PE that imports classic process-injection APIs"
        severity = "75"
    strings:
        $mz = { 4D 5A }
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        $mz and 2 of ($a,$b,$c)
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Common ransomware note phrasing"
        severity = "70"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
    condition:
        $a and 1 of ($b,$c)
}

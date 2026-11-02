# Downloads and verifies WinDivert and places WinDivert.dll + WinDivert64.sys
# next to adnesia.exe, for the experimental `-transparent` capture mode.
#
#   powershell -ExecutionPolicy Bypass -File fetch-windivert.ps1
#
# WinDivert is NOT vendored into this repo on purpose: its kernel driver is a
# signed binary you can't audit like source, and fetching it from the official
# signed release means you get the authentic driver with its signature intact
# (Windows verifies that signature when it loads the driver). This script pins
# the exact version and verifies the download's SHA-256 before using it.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$version  = "2.2.2"
$url      = "https://github.com/basil00/WinDivert/releases/download/v$version/WinDivert-$version-A.zip"
# SHA-256 of WinDivert-2.2.2-A.zip from the official GitHub release.
$expected = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15"

$tmp = Join-Path $env:TEMP ("windivert_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp "windivert.zip"
    Write-Host "Downloading WinDivert $version ..."
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    $hash = (Get-FileHash -Algorithm SHA256 $zip).Hash
    if ($hash -ne $expected) {
        throw "SHA-256 mismatch! got $hash, expected $expected. Aborting."
    }
    Write-Host "SHA-256 verified: $hash"

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $dll = Get-ChildItem -Recurse $tmp -Filter WinDivert.dll   | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
    $sys = Get-ChildItem -Recurse $tmp -Filter WinDivert64.sys | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
    if (-not $dll -or -not $sys) { throw "x64 WinDivert.dll / WinDivert64.sys not found in archive." }

    Copy-Item $dll.FullName (Join-Path $PSScriptRoot "WinDivert.dll")   -Force
    Copy-Item $sys.FullName (Join-Path $PSScriptRoot "WinDivert64.sys") -Force

    $sig = Get-AuthenticodeSignature (Join-Path $PSScriptRoot "WinDivert64.sys")
    Write-Host ("Driver signature: {0}" -f $sig.Status)
    Write-Host ("Signed by:        {0}" -f $sig.SignerCertificate.Subject)
    Write-Host "Placed WinDivert.dll + WinDivert64.sys next to adnesia.exe."
    Write-Host "Run 'adnesia.exe -transparent' (as administrator) to use it."
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

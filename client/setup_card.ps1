# setup_card.ps1 -- one-time IC-card seed installer (run as ADMIN).
#
# The game creates/reads C:\iccard.bin.  Creating a new card needs admin
# (C:\ root is not writable by a normal token); after seeding we drop the file
# to Low integrity and grant the current user modify, so later non-elevated
# runs can save to it.

param(
    [string]$Card = ''
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this script as Administrator (right-click -> Run as administrator)'
}

if (-not $Card) { $Card = Join-Path $Root 'card\iccard_seed.bin' }
if (-not (Test-Path $Card)) { throw "seed card not found: $Card" }

$dst = 'C:\iccard.bin'
if (Test-Path $dst) {
    $bak = Join-Path $Root ('card\iccard_prev_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.bin')
    Copy-Item $dst $bak -Force
    Write-Host "backed up existing card -> $bak"
}
Copy-Item $Card $dst -Force
& icacls $dst /setintegritylevel Low | Out-Null
& icacls $dst /grant "$($env:USERNAME):(M)" | Out-Null
Write-Host "seeded $dst from $Card"

# The DeviceUSB card backend also needs <drive>:\iccard.txt (the 20-char mark).
$txt = Join-Path $Root 'card\iccard.txt'
if (Test-Path $txt) {
    if (Test-Path 'C:\iccard.txt') { Copy-Item 'C:\iccard.txt' (Join-Path $Root 'card\iccard_prev.txt') -Force }
    Copy-Item $txt 'C:\iccard.txt' -Force
    & icacls 'C:\iccard.txt' /setintegritylevel Low | Out-Null
    & icacls 'C:\iccard.txt' /grant "$($env:USERNAME):(M)" | Out-Null
    Write-Host "seeded C:\iccard.txt (mark file)"
}
Write-Host ("size={0} sha256={1}" -f (Get-Item $dst).Length, (Get-FileHash $dst -Algorithm SHA256).Hash.Substring(0,16))

<#
.SYNOPSIS
  Takes an encrypted backup of the fraud engine's Supabase data.

.DESCRIPTION
  Pulls every row of every application table, encrypts the result with a
  password you choose, and writes it OUTSIDE this project directory - by
  default to "$HOME\Cubo Pago Backups".

  Outside is the whole point. This repository is public on GitHub. A dump of
  these tables contains card BINs, last-4 digits, merchant names and reviewer
  email addresses. .gitignore would keep it out of git, but .vercelignore is a
  separate file with separate rules, and a `vercel` CLI deploy uploads the
  working directory rather than cloning from GitHub. A file that is never in
  the directory cannot be uploaded by either path.

.EXAMPLE
  .\scripts\backup-database.ps1
#>
[CmdletBinding()]
param(
    # Where the encrypted backup lands. Must not be inside the repo.
    [string]$BackupRoot = (Join-Path $HOME 'Cubo Pago Backups'),

    # Stamped into the filename so a backup can be matched to the code that
    # produced it. Defaults to the git tag or short SHA you are sitting on.
    [string]$Label
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $here
. (Join-Path $here '_crypto.ps1')

function Write-Step($msg) { Write-Host "`n$msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "  $msg" -ForegroundColor Yellow }

# ── Refuse to write inside the repo ──────────────────────────────────────────
$resolvedRoot = [IO.Path]::GetFullPath($BackupRoot)
$resolvedRepo = [IO.Path]::GetFullPath($repo)
if ($resolvedRoot.TrimEnd('\').StartsWith($resolvedRepo.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to write backups inside the repository ($resolvedRoot). This repo is public; pick a folder outside it."
}

if (-not $Label) {
    Push-Location $repo
    try {
        $Label = (git describe --tags --exact-match 2>$null)
        if (-not $Label) { $Label = 'sha-' + (git rev-parse --short HEAD 2>$null) }
        if (-not $Label) { $Label = 'unlabelled' }
    } finally { Pop-Location }
}
$Label = ($Label -replace '[^\w\.\-]', '_').Trim()

Write-Host "Cubo Pago - encrypted database backup" -ForegroundColor White
Write-Host "Label:       $Label"
Write-Host "Destination: $resolvedRoot"

# ── Credentials ──────────────────────────────────────────────────────────────
# Reuse runner/.env when it is there (it is gitignored and already holds these)
# so the common case is no typing. Otherwise ask, and never echo either value.
Write-Step '1/4  Supabase credentials'
$supaUrl = $null; $supaKey = $null
$envFile = Join-Path $repo 'runner\.env'
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*(?<k>[A-Z_]+)\s*=\s*(?<v>.+?)\s*$') {
            $k = $Matches['k']; $v = $Matches['v'].Trim('"').Trim("'")
            if ($k -eq 'NEXT_PUBLIC_SUPABASE_URL')   { $supaUrl = $v }
            if ($k -eq 'SUPABASE_SERVICE_ROLE_KEY')  { $supaKey = $v }
        }
    }
    if ($supaUrl -and $supaKey) { Write-Ok "Read from runner\.env (key $($supaKey.Substring(0,6))...)" }
}
if (-not $supaUrl) {
    $supaUrl = Read-Host '  Supabase project URL (https://xxxx.supabase.co)'
}
if (-not $supaKey) {
    Write-Warn2 'The service-role key is not echoed as you paste it.'
    $secureKey = Read-Host '  Supabase service-role key' -AsSecureString
    $supaKey = ConvertFrom-SecureStringPlain $secureKey
}
if (-not $supaUrl -or -not $supaKey) { throw 'Both the project URL and the service-role key are required.' }

# ── Backup password ──────────────────────────────────────────────────────────
Write-Step '2/4  Backup password'
Write-Warn2 'There is no recovery if you lose this. Put it in your password manager now.'
$pw1 = Read-Host '  Choose a password' -AsSecureString
$pw2 = Read-Host '  Type it again'     -AsSecureString
$p1 = ConvertFrom-SecureStringPlain $pw1
$p2 = ConvertFrom-SecureStringPlain $pw2
if ($p1 -ne $p2)       { throw 'The two passwords do not match. Nothing was written.' }
if ($p1.Length -lt 12) { throw 'Use at least 12 characters. Nothing was written.' }
$p1 = $null; $p2 = $null
Write-Ok 'Passwords match.'

# ── Pull ─────────────────────────────────────────────────────────────────────
Write-Step '3/4  Reading Supabase'
if (-not (Test-Path $resolvedRoot)) { New-Item -ItemType Directory -Path $resolvedRoot -Force | Out-Null }

$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$plain = Join-Path $resolvedRoot ".tmp-$stamp.json"
$final = Join-Path $resolvedRoot "cubo-data_${Label}_$stamp.cubobak"

try {
    $env:SUPABASE_URL         = $supaUrl
    $env:SUPABASE_SERVICE_KEY = $supaKey
    $env:DUMP_OUT             = $plain
    python (Join-Path $here 'dump_supabase.py')
    if ($LASTEXITCODE -ne 0) { throw "The dump failed (exit $LASTEXITCODE). Nothing was written." }
} finally {
    $env:SUPABASE_URL = $null; $env:SUPABASE_SERVICE_KEY = $null; $env:DUMP_OUT = $null
    $supaKey = $null
}
if (-not (Test-Path $plain)) { throw 'The dump produced no file. Nothing was written.' }
Write-Ok ("Dumped {0:N0} KB of plaintext." -f ((Get-Item $plain).Length / 1KB))

# ── Encrypt, then destroy the plaintext ──────────────────────────────────────
Write-Step '4/4  Encrypting'
try {
    Protect-BackupFile -InPath $plain -OutPath $final -Password $pw1
} finally {
    # Overwrite before unlinking. Deleting a file leaves its bytes on the disk
    # for anything that reads raw sectors; this at least makes the obvious
    # recovery tools come back with noise.
    Remove-FileSecurely -Path $plain
}
Write-Ok "Wrote $final"
Write-Ok ("{0:N0} KB encrypted." -f ((Get-Item $final).Length / 1KB))

# ── Prove it can be restored ─────────────────────────────────────────────────
# A backup nobody has opened is a guess. Open it here, while the password is
# still in memory and the operator is still watching.
Write-Step 'Verifying the backup opens'
$check = Join-Path $resolvedRoot ".verify-$stamp.json"
try {
    Unprotect-BackupFile -InPath $final -OutPath $check -Password $pw1
    $parsed = Get-Content $check -Raw | ConvertFrom-Json
    $total  = 0
    foreach ($p in $parsed.meta.row_counts.PSObject.Properties) { $total += $p.Value }
    Write-Ok "Opened cleanly. $total rows across $($parsed.meta.row_counts.PSObject.Properties.Count) tables."
    Write-Ok "Taken at $($parsed.meta.taken_at)"
} finally {
    Remove-FileSecurely -Path $check
}

Write-Host "`nDone." -ForegroundColor Green
Write-Host "Restore with:  .\scripts\restore-database.ps1 -Path `"$final`"" -ForegroundColor White

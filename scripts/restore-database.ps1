<#
.SYNOPSIS
  Opens an encrypted backup, and optionally writes its rows back to Supabase.

.DESCRIPTION
  Two modes, and the safe one is the default:

    (no flag)   Decrypt and report what is inside. Nothing is written to
                Supabase. Nothing is left on disk unless you ask for it.
    -Apply      Actually push the rows back into Supabase.

  -Apply upserts. Rows in the backup overwrite rows with the same primary key;
  rows created after the backup was taken are left alone rather than deleted,
  because a restore that silently destroys newer work is worse than the problem
  it was run to fix. If a table genuinely must match the backup exactly, empty
  it deliberately first, then -Apply.

.EXAMPLE
  .\scripts\restore-database.ps1 -Path "$HOME\Cubo Pago Backups\cubo-data_v1.0.0_2026-09-13_1042.cubobak"

.EXAMPLE
  .\scripts\restore-database.ps1 -Path "...\cubo-data_v1.0.0_2026-09-13_1042.cubobak" -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,

    # Write the decrypted JSON here and leave it there. That file is cardholder
    # data in the clear - delete it when you are done with it.
    [string]$ExtractTo,

    # Without this, nothing is written to Supabase.
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $here
. (Join-Path $here '_crypto.ps1')

function Write-Step($msg) { Write-Host "`n$msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  $msg" -ForegroundColor Green }

if (-not (Test-Path $Path)) { throw "No such backup: $Path" }
Write-Host "Cubo Pago - restore from backup" -ForegroundColor White
Write-Host "Backup: $Path"

Write-Step '1/3  Decrypting'
$pw = Read-Host '  Backup password' -AsSecureString
if ($ExtractTo) {
    $tmp = $ExtractTo
} else {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('.cubo-restore-' + [Guid]::NewGuid().ToString('N') + '.json')
}
Unprotect-BackupFile -InPath $Path -OutPath $tmp -Password $pw
Write-Ok 'Opened.'

try {
    $parsed = Get-Content $tmp -Raw | ConvertFrom-Json

    Write-Step '2/3  What is inside'
    Write-Host "  Taken at: $($parsed.meta.taken_at)"
    Write-Host "  Format:   $($parsed.meta.format)"
    $total = 0
    foreach ($p in $parsed.meta.row_counts.PSObject.Properties) {
        Write-Host ("    {0,-22} {1,7:N0} rows" -f $p.Name, $p.Value)
        $total += $p.Value
    }
    Write-Ok "$total rows total."

    if (-not $Apply) {
        Write-Step '3/3  Stopping here'
        Write-Host '  Nothing was written to Supabase. Re-run with -Apply to push these rows back.' -ForegroundColor Yellow
        if ($ExtractTo) {
            Write-Host "  Decrypted copy left at $ExtractTo - that is cardholder data, delete it when done." -ForegroundColor Yellow
        }
        return
    }

    Write-Step '3/3  Writing back to Supabase'
    Write-Host '  This upserts every row above into the LIVE database.' -ForegroundColor Yellow
    $confirm = Read-Host '  Type RESTORE to continue'
    if ($confirm -cne 'RESTORE') { throw 'Cancelled. Nothing was written.' }

    $supaUrl = $null; $supaKey = $null
    $envFile = Join-Path $repo 'runner\.env'
    if (Test-Path $envFile) {
        foreach ($line in Get-Content $envFile) {
            if ($line -match '^\s*(?<k>[A-Z_]+)\s*=\s*(?<v>.+?)\s*$') {
                $k = $Matches['k']; $v = $Matches['v'].Trim('"').Trim("'")
                if ($k -eq 'NEXT_PUBLIC_SUPABASE_URL')  { $supaUrl = $v }
                if ($k -eq 'SUPABASE_SERVICE_ROLE_KEY') { $supaKey = $v }
            }
        }
    }
    if (-not $supaUrl) { $supaUrl = Read-Host '  Supabase project URL' }
    if (-not $supaKey) { $supaKey = ConvertFrom-SecureStringPlain (Read-Host '  Supabase service-role key' -AsSecureString) }

    try {
        $env:SUPABASE_URL         = $supaUrl
        $env:SUPABASE_SERVICE_KEY = $supaKey
        $env:RESTORE_IN           = $tmp
        # Same reason as the dump: progress goes to stderr, and calling python
        # directly would abort on the first line. See _crypto.ps1.
        $code = Invoke-NativeShow 'python' @((Join-Path $here 'restore_supabase.py')) -Indent '  '
        if ($code -ne 0) { throw "The restore failed (exit $code)." }
    } finally {
        $env:SUPABASE_URL = $null; $env:SUPABASE_SERVICE_KEY = $null; $env:RESTORE_IN = $null
        $supaKey = $null
    }
    Write-Ok 'Restore complete.'
} finally {
    if (-not $ExtractTo) { Remove-FileSecurely -Path $tmp }
}

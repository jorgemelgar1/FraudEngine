# Tests for the PowerShell half of the backup tooling.
#
#   powershell -ExecutionPolicy Bypass -File tests\test_backup_scripts.ps1
#
# These exist because scripts/backup-database.ps1 shipped having never been
# run, and then failed four times in a row on real use — each failure in a
# different line of the same short script:
#
#   1. `git describe` writes to stderr on an untagged commit, and PowerShell
#      5.1 turns native stderr into a TERMINATING error under 'Stop'.
#   2. dump_supabase.py reports progress on stderr, so it would have died the
#      same way one step later.
#   3. Ctrl+V in the classic console does not paste — it inserts 0x16, which
#      reached urllib as the whole URL.
#   4. PSObject.Properties has no .Count, which under Set-StrictMode aborted
#      the script on its LAST line, after a good 14 MB backup was written.
#
# None were subtle once seen, and all four were reachable by running the thing
# once. Every one is pinned below.
#
# Runs under the same `Stop` + `StrictMode -Latest` the real scripts use, so a
# test passing here means that combination is genuinely safe.
#
# All data here is fabricated, and nothing talks to a real project.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $Here
. (Join-Path $Repo 'scripts\_crypto.ps1')

$TmpDir = Join-Path ([IO.Path]::GetTempPath()) ("cubo-script-tests-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:Pass = 0
$script:Fail = 0

# Write-Host, never Write-Output: a PowerShell function returns everything on
# the output stream, so Write-Output here would be captured by any caller that
# assigns the result.
function Check($Name, $Ok, $Detail) {
    if ($Ok) { Write-Host "  PASS  $Name"; $script:Pass++ }
    else     { Write-Host "  FAIL  $Name"; $script:Fail++ }
    if ($Detail) { Write-Host "          $Detail" }
}

function Try-It($Name, $Block) {
    try { $r = & $Block; Check $Name $true ''; return $r }
    catch { Check $Name $false $_.Exception.Message; return $null }
}

function New-DumpFile($Path, $Counts) {
    $rc = [ordered]@{}; $tables = [ordered]@{}
    foreach ($k in $Counts.Keys) {
        $rc[$k] = $Counts[$k]
        $rows = @()
        for ($i = 0; $i -lt $Counts[$k]; $i++) { $rows += @{ id = "$k-$i" } }
        $tables[$k] = $rows
    }
    ([ordered]@{
        meta = [ordered]@{
            taken_at   = (Get-Date).ToUniversalTime().ToString('o')
            format     = 'cubo-fraud-engine-data-dump/1'
            row_counts = $rc
        }
        tables = $tables
    } | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $Path -Encoding utf8
}

$Password = ConvertTo-SecureString 'a-long-enough-backup-password' -AsPlainText -Force
$WrongPassword = ConvertTo-SecureString 'a-long-enough-backup-passwor' -AsPlainText -Force

Write-Host "`nEncryption" -ForegroundColor Cyan

$plain = Join-Path $TmpDir 'sample.json'
New-DumpFile $plain ([ordered]@{
    analysis_runs = 3; findings_history = 2; fraud_indicators = 0
    runner_cycles = 1; watchlist_cards = 4; watchlist_merchants = 1
})
# Make the plaintext contain the shapes that make this data sensitive.
$body = Get-Content -LiteralPath $plain -Raw
$body = $body -replace '"analysis_runs"', '"analysis_runs_411111_4242_cubopago"'
Set-Content -LiteralPath $plain -Value $body -Encoding utf8

$enc = Join-Path $TmpDir 'sample.cubobak'
$dec = Join-Path $TmpDir 'sample-out.json'
Protect-BackupFile -InPath $plain -OutPath $enc -Password $Password
Unprotect-BackupFile -InPath $enc -OutPath $dec -Password $Password

$a = [IO.File]::ReadAllBytes($plain); $b = [IO.File]::ReadAllBytes($dec)
$same = $a.Length -eq $b.Length
if ($same) { for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { $same = $false; break } } }
Check "round trip is byte-identical" $same "$($a.Length) bytes"

$cipherText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($enc))
Check "ciphertext leaks no BIN"        (-not $cipherText.Contains('411111')) ''
Check "ciphertext leaks no last-4"     (-not $cipherText.Contains('4242')) ''
Check "ciphertext leaks no domain"     (-not $cipherText.Contains('cubopago')) ''
Check "ciphertext leaks no table name" (-not $cipherText.Contains('analysis_runs')) ''

$refused = $false
try { Unprotect-BackupFile -InPath $enc -OutPath (Join-Path $TmpDir 'no.json') -Password $WrongPassword }
catch { $refused = $true }
Check "a wrong password is refused" $refused ''

$raw = [IO.File]::ReadAllBytes($enc)
$tampered = Join-Path $TmpDir 'tampered.cubobak'
$copy = New-Object byte[] $raw.Length
[Array]::Copy($raw, $copy, $raw.Length)
$mid = [int]($copy.Length / 2)
$copy[$mid] = $copy[$mid] -bxor 1
[IO.File]::WriteAllBytes($tampered, $copy)
$caught = $false
try { Unprotect-BackupFile -InPath $tampered -OutPath (Join-Path $TmpDir 'no2.json') -Password $Password }
catch { $caught = $true }
Check "a single flipped bit is caught by the HMAC" $caught ''

$enc2 = Join-Path $TmpDir 'sample2.cubobak'
Protect-BackupFile -InPath $plain -OutPath $enc2 -Password $Password
$r2 = [IO.File]::ReadAllBytes($enc2)
$differs = $false
for ($i = 0; $i -lt [Math]::Min($raw.Length, $r2.Length); $i++) { if ($raw[$i] -ne $r2[$i]) { $differs = $true; break } }
Check "same data encrypted twice differs (fresh salt and IV)" $differs ''

Write-Host "`nSecure delete" -ForegroundColor Cyan
$victim = Join-Path $TmpDir 'victim.json'
Set-Content -LiteralPath $victim -Value 'SECRET 411111 4242' -Encoding utf8
Remove-FileSecurely -Path $victim
Check "the file is gone" (-not (Test-Path $victim)) ''
Try-It "removing a file that is not there is not an error" { Remove-FileSecurely -Path (Join-Path $TmpDir 'never-existed.json') } | Out-Null

Write-Host "`nReading what a person typed" -ForegroundColor Cyan
# 0x16 is SYN, what Ctrl+V inserts in the classic console host.
$ctrlV = [char]0x16
Check "a failed Ctrl+V paste cleans to nothing" ((Remove-ControlCharacters "$ctrlV") -eq '') ''
Check "a real URL is untouched" ((Remove-ControlCharacters 'https://abcdefgh.supabase.co') -eq 'https://abcdefgh.supabase.co') ''
Check "surrounding whitespace is trimmed" ((Remove-ControlCharacters "  https://x.supabase.co  ") -eq 'https://x.supabase.co') ''
Check "a stray control char inside a key is repaired" ((Remove-ControlCharacters "sb_secret_abc$($ctrlV)def") -eq 'sb_secret_abcdef') ''

# The validators the real prompts use, kept in step with backup-database.ps1.
$urlOk = { param($v) $v -match '^https?://[^/\s]+\.[^/\s]+' }
$keyOk = { param($v) $v.Length -ge 20 -and $v -notmatch '\s' }
Check "URL check accepts a project URL"     (& $urlOk 'https://abcdefgh.supabase.co') ''
Check "URL check accepts a local server"    (& $urlOk 'http://127.0.0.1:8000/x') ''
Check "URL check rejects the Ctrl+V remnant" (-not (& $urlOk "$ctrlV")) ''
Check "URL check rejects a bare hostname"   (-not (& $urlOk 'abcdefgh.supabase.co')) ''
Check "key check accepts a JWT-style key"   (& $keyOk ('eyJ' + ('a' * 40))) ''
Check "key check accepts an sb_secret key"  (& $keyOk 'sb_secret_0123456789abcdef') ''
Check "key check rejects a truncated paste" (-not (& $keyOk 'eyJab')) ''
Check "key check rejects an internal space" (-not (& $keyOk 'sb_secret_0123456789abc def')) ''

Write-Host "`nDescribing a dump (the step that crashed after a good backup)" -ForegroundColor Cyan
$s = Try-It "summarising a decrypted dump does not throw under StrictMode" { Get-BackupSummary -JsonPath $dec }
if ($s) {
    Check "table count is right" ($s.TableCount -eq 6) "got $($s.TableCount)"
    Check "row total is right"   ($s.TotalRows -eq 11) "got $($s.TotalRows)"
    Check "an empty table is still listed" (@($s.Tables | Where-Object { $_.Count -eq 0 }).Count -eq 1) ''
    Check "format is read back"  ($s.Format -eq 'cubo-fraud-engine-data-dump/1') ''
    Check "taken_at is read back" (-not [string]::IsNullOrWhiteSpace($s.TakenAt)) ''
}

# A one-property object is the case where PowerShell does not produce a
# collection at all, so .Count is absent unless @() forces an array.
$one = Join-Path $TmpDir 'one.json'
New-DumpFile $one ([ordered]@{ runner_cycles = 1 })
$s1 = Try-It "a single-table dump does not throw" { Get-BackupSummary -JsonPath $one }
if ($s1) { Check "a single table counts as 1" ($s1.TableCount -eq 1) "got $($s1.TableCount)" }

$zero = Join-Path $TmpDir 'zero.json'
New-DumpFile $zero ([ordered]@{ analysis_runs = 0; runner_cycles = 0 })
$s0 = Try-It "an all-empty dump does not throw" { Get-BackupSummary -JsonPath $zero }
if ($s0) { Check "an all-empty dump totals zero" ($s0.TotalRows -eq 0) "got $($s0.TotalRows)" }

# StrictMode makes reading an absent property terminating, so malformed
# metadata has to be guarded rather than assumed.
$noMeta = Join-Path $TmpDir 'nometa.json'
'{"tables":{}}' | Set-Content -LiteralPath $noMeta -Encoding utf8
$sb = Try-It "a dump with no meta block does not throw" { Get-BackupSummary -JsonPath $noMeta }
if ($sb) { Check "says unknown rather than inventing" ($sb.Format -eq '(unknown)' -and $sb.TotalRows -eq 0) '' }

$noCounts = Join-Path $TmpDir 'nocounts.json'
'{"meta":{"taken_at":"2026-01-01"},"tables":{}}' | Set-Content -LiteralPath $noCounts -Encoding utf8
$sb2 = Try-It "meta without row_counts does not throw" { Get-BackupSummary -JsonPath $noCounts }
if ($sb2) { Check "no row_counts means zero tables" ($sb2.TableCount -eq 0) "got $($sb2.TableCount)" }

Write-Host "`nCalling other programs" -ForegroundColor Cyan
Push-Location $Repo
try {
    $label = Try-It "git describe on an untagged commit does not abort" {
        Invoke-NativeCapture 'git' @('describe', '--tags', '--exact-match')
    }
    if (-not $label) {
        $sha = Invoke-NativeCapture 'git' @('rev-parse', '--short', 'HEAD')
        Check "falls back to a short SHA" ($sha -match '^[0-9a-f]{7,}$') "sha = $sha"
    } else {
        Check "a tagged commit returns its tag" ($label -match '^v\d') "tag = $label"
    }
} finally { Pop-Location }

$noisy = Join-Path $TmpDir 'noisy.py'
@'
import sys
print("  analysis_runs   1,200 rows", file=sys.stderr)
sys.exit(0)
'@ | Set-Content -LiteralPath $noisy -Encoding utf8
$code = Try-It "stderr from a SUCCESSFUL program does not abort" { Invoke-NativeShow 'python' @($noisy) }
Check "a successful program reports 0" ($code -eq 0) "got $code"

$failing = Join-Path $TmpDir 'failing.py'
@'
import sys
print("ERROR: something went wrong", file=sys.stderr)
sys.exit(1)
'@ | Set-Content -LiteralPath $failing -Encoding utf8
$code2 = Try-It "a failing program does not abort either" { Invoke-NativeShow 'python' @($failing) }
Check "a failing program reports non-zero" ($code2 -eq 1) "got $code2"

$missing = Try-It "a missing executable is handled, not thrown" {
    Invoke-NativeCapture 'definitely-not-a-real-program-xyz' @('--version')
}
Check "a missing executable yields nothing" ($null -eq $missing) ''

Write-Host "`nScripts parse" -ForegroundColor Cyan
foreach ($f in @('_crypto.ps1', 'backup-database.ps1', 'restore-database.ps1')) {
    $p = Join-Path $Repo "scripts\$f"
    $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errs)
    Check "$f parses" (@($errs).Count -eq 0) (($errs | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')
}

Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "$script:Pass passed, $script:Fail failed"
if ($script:Fail -gt 0) { exit 1 }
exit 0

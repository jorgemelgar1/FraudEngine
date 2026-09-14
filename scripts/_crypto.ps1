# AES-256 file encryption for the database backups.
#
# Why this exists instead of a one-line call to something else: 7-Zip is not
# installed on this laptop, and EFS - the encryption built into Windows - is
# not available on Home editions, which is what this machine runs. That leaves
# .NET, which is already present. Nothing here needs installing.
#
# The threat this actually defends against is a stolen or resold laptop, or a
# backup file copied somewhere careless. It is not defending against someone
# who already has the password.
#
# File layout, in order:
#   magic      8 bytes   "CUBOBAK1", so a wrong file fails loudly not weirdly
#   iterations 4 bytes   how many PBKDF2 rounds, so this stays readable if the
#                        count is raised later and old files must still open
#   salt      16 bytes   fresh per file - identical passwords, different keys
#   iv        16 bytes   fresh per file
#   ciphertext n bytes
#   hmac      32 bytes   HMAC-SHA256 over everything above
#
# Encrypt-then-MAC, with a separate key for the MAC. The HMAC is the part that
# matters most for a backup: without it, a single flipped bit on disk decrypts
# to plausible-looking garbage SQL, and you find out on the day you restore.
# With it, a damaged file refuses to open and says so.

$script:BackupMagic      = [Text.Encoding]::ASCII.GetBytes('CUBOBAK1')
$script:BackupIterations = 310000   # OWASP's PBKDF2-SHA256 floor

function Get-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ,$bytes
}

function ConvertFrom-SecureStringPlain {
    # The KDF needs the password as a string. Keep that string alive for as
    # short a time as possible and wipe the unmanaged copy either way.
    param([System.Security.SecureString]$Secure)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
}

function Get-BackupKeys {
    # One password -> 64 bytes -> two independent 32-byte keys. Never reuse a
    # single key for both encryption and authentication.
    param([string]$Password, [byte[]]$Salt, [int]$Iterations)
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Password, $Salt, $Iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $material = $kdf.GetBytes(64)
        return @{ Aes = [byte[]]$material[0..31]; Hmac = [byte[]]$material[32..63] }
    } finally { $kdf.Dispose() }
}

function Protect-BackupFile {
    param(
        [Parameter(Mandatory)][string]$InPath,
        [Parameter(Mandatory)][string]$OutPath,
        [Parameter(Mandatory)][System.Security.SecureString]$Password
    )
    $plain = [IO.File]::ReadAllBytes($InPath)
    $salt  = Get-RandomBytes 16
    $pw    = ConvertFrom-SecureStringPlain $Password
    $keys  = Get-BackupKeys $pw $salt $script:BackupIterations
    $pw    = $null

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = [byte[]]$keys.Aes
        $aes.GenerateIV()

        $encryptor = $aes.CreateEncryptor()
        try { $cipher = $encryptor.TransformFinalBlock($plain, 0, $plain.Length) }
        finally { $encryptor.Dispose() }

        $header = New-Object Collections.Generic.List[byte]
        $header.AddRange($script:BackupMagic)
        $header.AddRange([BitConverter]::GetBytes([int]$script:BackupIterations))
        $header.AddRange([byte[]]$salt)
        $header.AddRange([byte[]]$aes.IV)

        $body = New-Object Collections.Generic.List[byte]
        $body.AddRange($header)
        $body.AddRange([byte[]]$cipher)

        $hmac = New-Object System.Security.Cryptography.HMACSHA256(,[byte[]]$keys.Hmac)
        try { $tag = $hmac.ComputeHash($body.ToArray()) } finally { $hmac.Dispose() }
        $body.AddRange([byte[]]$tag)

        [IO.File]::WriteAllBytes($OutPath, $body.ToArray())
    } finally {
        $aes.Dispose()
        [Array]::Clear($plain, 0, $plain.Length)
    }
}

function Unprotect-BackupFile {
    param(
        [Parameter(Mandatory)][string]$InPath,
        [Parameter(Mandatory)][string]$OutPath,
        [Parameter(Mandatory)][System.Security.SecureString]$Password
    )
    $raw = [IO.File]::ReadAllBytes($InPath)
    if ($raw.Length -lt 92) { throw "Not a backup file - too short to be one." }

    $magic = [byte[]]$raw[0..7]
    if ([Text.Encoding]::ASCII.GetString($magic) -ne 'CUBOBAK1') {
        throw "Not a Cubo backup file (bad magic). Is this the right file?"
    }
    $iterations = [BitConverter]::ToInt32($raw, 8)
    $salt = [byte[]]$raw[12..27]
    $iv   = [byte[]]$raw[28..43]
    $tag      = [byte[]]$raw[($raw.Length - 32)..($raw.Length - 1)]
    $signed   = [byte[]]$raw[0..($raw.Length - 33)]
    $cipher   = [byte[]]$raw[44..($raw.Length - 33)]

    $pw   = ConvertFrom-SecureStringPlain $Password
    $keys = Get-BackupKeys $pw $salt $iterations
    $pw   = $null

    # Verify before decrypting. A wrong password and a corrupted file both stop
    # here, which is why the message names both possibilities.
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,[byte[]]$keys.Hmac)
    try { $actual = $hmac.ComputeHash($signed) } finally { $hmac.Dispose() }

    $ok = $actual.Length -eq $tag.Length
    if ($ok) {
        # Constant-time compare. Cheap, and avoids a timing oracle on the tag.
        $diff = 0
        for ($i = 0; $i -lt $tag.Length; $i++) { $diff = $diff -bor ($actual[$i] -bxor $tag[$i]) }
        $ok = ($diff -eq 0)
    }
    if (-not $ok) {
        throw "Could not open the backup: wrong password, or the file is damaged."
    }

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = [byte[]]$keys.Aes
        $aes.IV      = [byte[]]$iv
        $decryptor = $aes.CreateDecryptor()
        try { $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length) }
        finally { $decryptor.Dispose() }
        [IO.File]::WriteAllBytes($OutPath, $plain)
        [Array]::Clear($plain, 0, $plain.Length)
    } finally { $aes.Dispose() }
}

# ── Reading values a human typed or pasted ──────────────────────────────────
#
# In the classic Windows console host, Ctrl+V is NOT paste. It inserts the
# control character 0x16 (SYN) and nothing else happens. The prompt looks like
# it accepted something, the variable holds one invisible character, and the
# failure surfaces much later somewhere unrelated — in the first version of
# this script, as a Python traceback reading
#
#   ValueError: unknown url type: '\x16/rest/v1/analysis_runs?select=%2A'
#
# thirty seconds and two prompts after the mistake was made. Pasting works
# there with a right-click, or with Ctrl+V in Windows Terminal and VS Code.
#
# Rather than explain that and hope, these helpers strip control characters
# and check the value looks like what was asked for, at the prompt, while the
# person is still standing at it.

function Remove-ControlCharacters {
    # Strip the invisible characters a failed console paste leaves behind.
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace '[\x00-\x1F\x7F]', '').Trim()
}


function Read-CheckedValue {
    <#
    .SYNOPSIS
      Prompt until the answer passes `Validate`, or give up after `MaxTries`.
    .DESCRIPTION
      `Secret` hides typing. `Hint` is what the person is told when the value
      does not pass — say what a good value looks like, not just "invalid".
      Gives up rather than looping forever, so a redirected stdin (no console)
      fails fast instead of spinning.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Validate,
        [string]$Hint = '',
        [switch]$Secret,
        [int]$MaxTries = 3
    )
    for ($attempt = 1; $attempt -le $MaxTries; $attempt++) {
        if ($Secret) {
            $raw = ConvertFrom-SecureStringPlain (Read-Host $Prompt -AsSecureString)
        } else {
            $raw = Read-Host $Prompt
        }
        $value = Remove-ControlCharacters $raw

        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host '    Nothing came through. If you used Ctrl+V, try right-click to paste instead.' -ForegroundColor Yellow
            continue
        }
        if ($Validate -and -not (& $Validate $value)) {
            if ($Hint) { Write-Host "    $Hint" -ForegroundColor Yellow }
            continue
        }
        return $value
    }
    throw "Gave up after $MaxTries attempts at: $Prompt"
}


# ── Running other programs without PowerShell killing the script ────────────
#
# Windows PowerShell 5.1 wraps every line a native program writes to stderr in
# an ErrorRecord. Under `$ErrorActionPreference = 'Stop'` that ErrorRecord is a
# TERMINATING error, so a program that merely talks on stderr aborts the whole
# script even when it succeeded and returned 0.
#
# This is not theoretical and `2>$null` does not fix it: it is the wrapping,
# not the stream, that throws. Two real cases here:
#
#   git describe --tags --exact-match   says "fatal: no tag exactly matches"
#                                       on any untagged commit, which is the
#                                       normal state between releases
#   python dump_supabase.py             prints its per-table progress to
#                                       stderr on purpose, so stdout stays
#                                       clean for data
#
# Both are ordinary output. Neither is a reason to stop. These two helpers are
# the only sanctioned way to call a native program from these scripts.

function Invoke-NativeCapture {
    <#
    .SYNOPSIS
      Run a program, return its trimmed stdout, or $null if it failed.
    .DESCRIPTION
      For programs whose OUTPUT you want and whose complaints you do not.
      Never throws: a non-zero exit, a missing executable and an empty result
      are all reported as $null, so the caller decides what a failure means.
    #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @()
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Command @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($null -eq $out) { return $null }
        $text = ($out | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return $text
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Invoke-NativeShow {
    <#
    .SYNOPSIS
      Run a program, show everything it prints, return its exit code.
    .DESCRIPTION
      For long-running steps where the operator should watch progress. stdout
      and stderr are merged and echoed in order; the exit code is what decides
      success, which is the only thing that ever should have decided it.
    #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @(),
        [string]$Indent = '  '
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Command @Arguments 2>&1 | ForEach-Object {
            $line = if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.Exception.Message
            } else { "$_" }
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Host "$Indent$line"
            }
        }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($null -eq $code) { return 0 }
    return $code
}


function Get-BackupSummary {
    <#
    .SYNOPSIS
      Describe a decrypted dump: when it was taken, and how many rows per table.
    .DESCRIPTION
      Shared by backup-database.ps1 (verifying what it just wrote) and
      restore-database.ps1 (reporting what it is about to write), which used
      to carry two copies of this walk.

      Every property access here is guarded, because `Set-StrictMode -Version
      Latest` makes reading a property that does not exist a TERMINATING
      error. A copy of this code crashed on `PSObject.Properties.Count` —
      PSMemberInfoCollection has no .Count — and took the script down on its
      last line, after a good 14 MB backup had already been written and
      verified. The backup was fine; the sentence describing it was not.

      Returns an object with TakenAt, Format, Tables (Name/Count pairs),
      TableCount and TotalRows. Never throws on a well-formed dump.
    #>
    param([Parameter(Mandatory)][string]$JsonPath)

    $parsed = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json

    $meta = $null
    if ($parsed.PSObject.Properties.Match('meta').Count -gt 0) { $meta = $parsed.meta }

    $takenAt = '(unknown)'
    $format = '(unknown)'
    $rowCounts = $null
    if ($meta) {
        if ($meta.PSObject.Properties.Match('taken_at').Count -gt 0) { $takenAt = $meta.taken_at }
        if ($meta.PSObject.Properties.Match('format').Count -gt 0) { $format = $meta.format }
        if ($meta.PSObject.Properties.Match('row_counts').Count -gt 0) { $rowCounts = $meta.row_counts }
    }

    # @() forces a real array. PSObject.Properties is a PSMemberInfoCollection,
    # which has no .Count, and a single-property object would otherwise not be
    # a collection at all.
    $tables = @()
    $total = 0
    if ($rowCounts) {
        foreach ($p in @($rowCounts.PSObject.Properties)) {
            $count = 0
            if ($null -ne $p.Value) { $count = [int]$p.Value }
            $tables += [pscustomobject]@{ Name = $p.Name; Count = $count }
            $total += $count
        }
    }

    return [pscustomobject]@{
        TakenAt    = $takenAt
        Format     = $format
        Tables     = $tables
        TableCount = @($tables).Count
        TotalRows  = $total
    }
}


function Remove-FileSecurely {
    # The decrypted dump is the one moment card data touches this disk in the
    # clear. Delete alone only unlinks it - the bytes stay in the sectors until
    # something else claims them, which undelete tools are built to exploit.
    # Overwriting first does not defeat a forensics lab (SSD wear levelling
    # keeps copies you cannot reach from here), but it does defeat every tool
    # someone would actually point at a resold laptop.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $len = (Get-Item $Path).Length
        if ($len -gt 0) {
            $fs = [IO.File]::OpenWrite($Path)
            try {
                $chunk = New-Object byte[] ([Math]::Min($len, 1MB))
                $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                try {
                    $written = 0
                    while ($written -lt $len) {
                        $n = [Math]::Min($chunk.Length, $len - $written)
                        $rng.GetBytes($chunk)
                        $fs.Write($chunk, 0, $n)
                        $written += $n
                    }
                    $fs.Flush($true)
                } finally { $rng.Dispose() }
            } finally { $fs.Dispose() }
        }
    } catch {
        Write-Warning "Could not overwrite $Path before deleting it: $($_.Exception.Message)"
    }
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

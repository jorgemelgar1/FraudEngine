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

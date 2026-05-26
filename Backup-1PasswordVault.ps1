#Requires -Version 5.1
<#
.SYNOPSIS
    1Password Vault Backup Utility — SSO-Compatible Offline Backup

.DESCRIPTION
    Exports all accessible 1Password vault items (including concealed/password
    fields) to an AES-256 encrypted backup file using the 1Password CLI (op).

    This works with SSO accounts because authentication is delegated to the
    unlocked 1Password desktop app rather than requiring the master password.
    The built-in "Export" GUI restriction does not apply to the CLI.

    The output file is AES-256-CBC encrypted with a PBKDF2-derived key so it
    is safe to store on an encrypted external drive (BitLocker) or in a
    protected cloud location such as OneDrive Personal Vault.

.PARAMETER DestinationPath
    Folder where the encrypted .1pbak file will be saved.
    Should be an encrypted location (BitLocker drive, OneDrive Personal Vault, etc.)
    Defaults to the current directory.

.PARAMETER VaultName
    Restrict the backup to a single named vault. Omit to back up ALL accessible vaults.

.PARAMETER IncludeDocuments
    Also download Document items (file attachments) and embed them as Base64 in
    the backup. Can significantly increase backup size and duration for large vaults.

.PARAMETER AccountShorthand
    The 1Password account shorthand (e.g. "mycompany" from mycompany.1password.com).
    Required only when multiple accounts are added to the desktop app and you want
    to target a specific one.

.EXAMPLE
    .\Backup-1PasswordVault.ps1 -DestinationPath "D:\Secure"

.EXAMPLE
    .\Backup-1PasswordVault.ps1 -DestinationPath "D:\Secure" -VaultName "Personal" -IncludeDocuments

.EXAMPLE
    .\Backup-1PasswordVault.ps1 -DestinationPath "D:\Secure" -AccountShorthand "mycompany"

.NOTES
    Prerequisites:
      1. 1Password CLI (op) installed from https://developer.1password.com/docs/cli/get-started/
      2. 1Password desktop app open and unlocked (SSO or otherwise)
      3. CLI integration enabled in the app:
           Settings > Developer > Integrate with 1Password CLI
      4. PowerShell 5.1+ on Windows (uses .NET System.Security.Cryptography)

    The encrypted backup format (.1pbak):
      [4 bytes]  Magic: 0x31 0x50 0x42 0x4B  ("1PBK")
      [4 bytes]  Format version (little-endian uint32 = 1)
      [4 bytes]  PBKDF2 iteration count (little-endian uint32)
      [32 bytes] PBKDF2 salt
      [16 bytes] AES IV
      [N bytes]  AES-256-CBC encrypted payload (UTF-8 JSON, PKCS7 padded)

    To decrypt manually (e.g. with a custom tool), derive the key as:
      PBKDF2-HMAC-SHA256(password, salt, iterations, keyLength=32)
    then AES-256-CBC decrypt with that key and the stored IV.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$DestinationPath = $PSScriptRoot,

    [Parameter()]
    [string]$VaultName,

    [Parameter()]
    [switch]$IncludeDocuments,

    [Parameter()]
    [string]$AccountShorthand
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ──────────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [!]  $Message" -ForegroundColor Yellow
}

function Invoke-Op {
    <#
    Runs an `op` command and returns parsed JSON or raw string output.
    Throws on non-zero exit code.
    #>
    param(
        [string[]]$Arguments,
        [switch]$Raw       # return raw string instead of parsed JSON
    )

    $output = & op @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errText = $output | Out-String
        throw "op CLI error (exit $LASTEXITCODE): $errText"
    }

    if ($Raw) {
        return ($output | Out-String).Trim()
    }
    return $output | Out-String | ConvertFrom-Json
}

function New-AesEncryptedBytes {
    <#
    Encrypts a byte array with AES-256-CBC using a PBKDF2-derived key.
    Returns a byte array in the .1pbak format described in the header.
    #>
    param(
        [byte[]]$PlainBytes,
        [SecureString]$Password,
        [int]$Iterations = 600000   # NIST recommended minimum for PBKDF2-SHA256 (2023)
    )

    # Convert SecureString to plain bytes without leaving a managed string
    $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passStr  = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $passBytes = [System.Text.Encoding]::UTF8.GetBytes($passStr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $passStr  = $null

    try {
        # Generate random salt and derive key
        $salt = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $passBytes, $salt, $Iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $key = $pbkdf2.GetBytes(32)   # 256-bit AES key
        $pbkdf2.Dispose()

        # Encrypt
        $aes           = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key       = $key
        $aes.GenerateIV()
        $iv            = $aes.IV

        $encryptor   = $aes.CreateEncryptor()
        $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
        $encryptor.Dispose()
        $aes.Dispose()

        # Assemble file:  magic(4) + version(4) + iterations(4) + salt(32) + iv(16) + cipher
        $magic     = [byte[]]@(0x31, 0x50, 0x42, 0x4B)          # "1PBK"
        $version   = [System.BitConverter]::GetBytes([uint32]1)
        $iterBytes = [System.BitConverter]::GetBytes([uint32]$Iterations)

        $result = New-Object System.IO.MemoryStream
        $result.Write($magic,     0, $magic.Length)
        $result.Write($version,   0, $version.Length)
        $result.Write($iterBytes, 0, $iterBytes.Length)
        $result.Write($salt,      0, $salt.Length)
        $result.Write($iv,        0, $iv.Length)
        $result.Write($cipherBytes, 0, $cipherBytes.Length)

        return $result.ToArray()
    }
    finally {
        # Zero out sensitive bytes
        if ($null -ne $passBytes) { [Array]::Clear($passBytes, 0, $passBytes.Length) }
    }
}

function ConvertFrom-AesEncryptedBytes {
    <#
    Decrypts a .1pbak byte array. Exported for informational purposes / disaster recovery.
    Not called during backup — only useful if you build a restore tool.
    #>
    param(
        [byte[]]$EncryptedBytes,
        [SecureString]$Password
    )

    $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passStr  = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $passBytes = [System.Text.Encoding]::UTF8.GetBytes($passStr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $passStr  = $null

    try {
        $ms = New-Object System.IO.BinaryReader([System.IO.MemoryStream]::new($EncryptedBytes))

        $magic    = $ms.ReadBytes(4)
        if (-not ([System.Linq.Enumerable]::SequenceEqual($magic, [byte[]]@(0x31,0x50,0x42,0x4B)))) {
            throw "Invalid magic bytes — not a .1pbak file."
        }
        $null     = $ms.ReadBytes(4)   # version
        $iters    = [System.BitConverter]::ToUInt32($ms.ReadBytes(4), 0)
        $salt     = $ms.ReadBytes(32)
        $iv       = $ms.ReadBytes(16)
        $cipher   = $ms.ReadBytes($EncryptedBytes.Length - 60)
        $ms.Dispose()

        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $passBytes, $salt, [int]$iters,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $key = $pbkdf2.GetBytes(32)
        $pbkdf2.Dispose()

        $aes           = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key       = $key
        $aes.IV        = $iv

        $decryptor  = $aes.CreateDecryptor()
        $plainBytes = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
        $decryptor.Dispose()
        $aes.Dispose()

        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    finally {
        if ($null -ne $passBytes) { [Array]::Clear($passBytes, 0, $passBytes.Length) }
    }
}

#endregion

#region ── Preflight checks ────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║          1Password Vault Backup — SSO Compatible             ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host ""

# 1. Check op CLI is on PATH
Write-Step "Checking for 1Password CLI (op)..."
$opPath = Get-Command op -ErrorAction SilentlyContinue
if (-not $opPath) {
    Write-Error @"
The 1Password CLI (op) was not found on PATH.

Install it from: https://developer.1password.com/docs/cli/get-started/
  Windows (winget): winget install AgileBits.1Password.CLI
  Windows (manual): https://app-updates.agilebits.com/product_history/CLI2

After installing, ensure CLI integration is enabled in the 1Password app:
  Settings > Developer > Integrate with 1Password CLI
"@
    exit 1
}
Write-OK "Found op at: $($opPath.Source)"

# 2. Check destination path exists
Write-Step "Validating destination path..."
if (-not (Test-Path -Path $DestinationPath -PathType Container)) {
    Write-Error "Destination path does not exist: $DestinationPath"
    exit 1
}
Write-OK "Destination: $DestinationPath"

# 3. Verify op CLI can talk to the desktop app (user must be signed in)
Write-Step "Verifying 1Password authentication..."
$whoamiArgs = @('whoami', '--format', 'json')
if ($AccountShorthand) { $whoamiArgs += @('--account', $AccountShorthand) }

try {
    $identity = Invoke-Op -Arguments $whoamiArgs
    Write-OK "Authenticated as: $($identity.email) ($($identity.url))"
}
catch {
    Write-Error @"
Unable to authenticate with 1Password CLI.

Make sure:
  1. The 1Password desktop app is open and unlocked (SSO session active).
  2. CLI integration is enabled: Settings > Developer > Integrate with 1Password CLI
  3. If this is a first-time connection, run 'op signin' manually once to approve access.

Error detail: $_
"@
    exit 1
}

#endregion

#region ── Collect encryption password ─────────────────────────────────────────

Write-Host ""
Write-Host "  The backup will be encrypted with AES-256 (PBKDF2-SHA256)." -ForegroundColor White
Write-Host "  Choose a strong passphrase — you will need it to restore." -ForegroundColor White
Write-Host ""

$pass1 = $null
$pass2 = $null
do {
    $pass1 = Read-Host -AsSecureString "  Enter backup passphrase"
    $pass2 = Read-Host -AsSecureString "  Confirm backup passphrase"

    # Compare SecureStrings
    $p1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1)
    $p2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2)
    $match = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($p1) -ceq `
             [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($p2)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p2)

    if (-not $match) {
        Write-Warn "Passphrases do not match. Please try again."
    }
} while (-not $match)

Write-OK "Passphrase accepted."
Write-Host ""

#endregion

#region ── Enumerate vaults ─────────────────────────────────────────────────────

Write-Step "Enumerating vaults..."
$vaultArgs = @('vault', 'list', '--format', 'json')
if ($AccountShorthand) { $vaultArgs += @('--account', $AccountShorthand) }

$allVaults = Invoke-Op -Arguments $vaultArgs

if ($VaultName) {
    $allVaults = $allVaults | Where-Object { $_.name -eq $VaultName }
    if (-not $allVaults) {
        Write-Error "No vault named '$VaultName' was found."
        exit 1
    }
    Write-OK "Targeting vault: $VaultName"
}
else {
    Write-OK "Found $($allVaults.Count) vault(s)."
}

#endregion

#region ── Export items ─────────────────────────────────────────────────────────

$backupPayload = [ordered]@{
    formatVersion    = 1
    exportedAt       = (Get-Date -Format 'o')        # ISO 8601
    exportedBy       = $identity.email
    account          = $identity.url
    vaults           = @()
}

$totalItems = 0
$totalVaults = 0

foreach ($vault in $allVaults) {
    Write-Step "Processing vault: '$($vault.name)' [$($vault.id)]"

    $vaultExport = [ordered]@{
        id    = $vault.id
        name  = $vault.name
        type  = if ($vault.PSObject.Properties['type']) { $vault.type } else { 'UNKNOWN' }
        items = @()
    }

    # List all items in this vault
    $itemListArgs = @('item', 'list', '--vault', $vault.id, '--format', 'json')
    if ($AccountShorthand) { $itemListArgs += @('--account', $AccountShorthand) }

    try {
        $itemList = Invoke-Op -Arguments $itemListArgs
    }
    catch {
        Write-Warn "Could not list items in vault '$($vault.name)': $_"
        $backupPayload.vaults += $vaultExport
        continue
    }

    if (-not $itemList -or $itemList.Count -eq 0) {
        Write-Warn "  Vault '$($vault.name)' is empty or not accessible."
        $backupPayload.vaults += $vaultExport
        continue
    }

    Write-Host "    Found $($itemList.Count) item(s). Retrieving details..." -ForegroundColor DarkCyan

    $itemIndex = 0
    foreach ($itemRef in $itemList) {
        $itemIndex++
        $pct = [int](($itemIndex / $itemList.Count) * 100)
        Write-Progress -Activity "Backing up vault: $($vault.name)" `
                       -Status "$itemIndex of $($itemList.Count): $($itemRef.title)" `
                       -PercentComplete $pct

        $getArgs = @('item', 'get', $itemRef.id,
                     '--vault', $vault.id,
                     '--format', 'json',
                     '--reveal')          # <-- exposes concealed/password fields
        if ($AccountShorthand) { $getArgs += @('--account', $AccountShorthand) }

        try {
            $fullItem = Invoke-Op -Arguments $getArgs
        }
        catch {
            Write-Warn "  Failed to retrieve item '$($itemRef.title)' ($($itemRef.id)): $_"
            continue
        }

        # Optionally download Document/file attachments
        if ($IncludeDocuments -and $itemRef.category -eq 'DOCUMENT') {
            $docArgs = @('document', 'get', $itemRef.id,
                         '--vault', $vault.id)
            if ($AccountShorthand) { $docArgs += @('--account', $AccountShorthand) }

            try {
                $docBytes = & op @docArgs 2>$null
                if ($LASTEXITCODE -eq 0 -and $docBytes) {
                    # Embed as Base64 in the JSON
                    $fullItem | Add-Member -NotePropertyName '_documentContentBase64' `
                                           -NotePropertyValue ([Convert]::ToBase64String(
                                               [System.Text.Encoding]::UTF8.GetBytes(
                                                   ($docBytes | Out-String))))
                }
            }
            catch {
                Write-Warn "  Could not download document '$($itemRef.title)': $_"
            }
        }

        $vaultExport.items += $fullItem
        $totalItems++
    }

    Write-Progress -Activity "Backing up vault: $($vault.name)" -Completed
    Write-OK "  Exported $($vaultExport.items.Count) items from '$($vault.name)'."

    $backupPayload.vaults += $vaultExport
    $totalVaults++
}

Write-OK "Total: $totalItems item(s) across $totalVaults vault(s) collected."

#endregion

#region ── Serialize, encrypt, and write ────────────────────────────────────────

Write-Host ""
Write-Step "Serializing backup data..."
$jsonString = $backupPayload | ConvertTo-Json -Depth 20 -Compress
$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonString)
Write-OK "Unencrypted payload: $([Math]::Round($plainBytes.Length / 1KB, 1)) KB"

Write-Step "Encrypting with AES-256-CBC / PBKDF2-SHA256 (600,000 iterations)..."
$encryptedBytes = New-AesEncryptedBytes -PlainBytes $plainBytes -Password $pass1

# Zero the plaintext immediately after encryption
[Array]::Clear($plainBytes, 0, $plainBytes.Length)
$jsonString = $null

Write-OK "Encrypted payload: $([Math]::Round($encryptedBytes.Length / 1KB, 1)) KB"

# Build filename
$timestamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$accountLabel = ($identity.url -replace '[^a-zA-Z0-9]', '-').Trim('-')
$fileName     = "${timestamp}_1Password_Backup_${accountLabel}.1pbak"
$outPath      = Join-Path $DestinationPath $fileName

Write-Step "Writing encrypted backup to: $outPath"
[System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)

# Verify the file was written correctly
$written = (Get-Item $outPath).Length
if ($written -ne $encryptedBytes.Length) {
    Write-Error "File size mismatch after write ($written vs $($encryptedBytes.Length) bytes). Backup may be corrupt."
    exit 1
}

Write-OK "Backup file written ($([Math]::Round($written / 1KB, 1)) KB)."

#endregion

#region ── Self-test decrypt (sanity check) ────────────────────────────────────

Write-Step "Verifying backup integrity (test decrypt)..."
try {
    $readBack     = [System.IO.File]::ReadAllBytes($outPath)
    $decrypted    = ConvertFrom-AesEncryptedBytes -EncryptedBytes $readBack -Password $pass1
    $parsed       = $decrypted | ConvertFrom-Json
    $vaultCount   = $parsed.vaults.Count
    $itemCount    = ($parsed.vaults | ForEach-Object { $_.items.Count } | Measure-Object -Sum).Sum
    Write-OK "Integrity check passed. Backup contains $itemCount item(s) in $vaultCount vault(s)."
}
catch {
    Write-Warn "Integrity check failed: $_"
    Write-Warn "The backup file was written but could not be verified. Keep with caution."
}
finally {
    $decrypted = $null
    $readBack  = $null
}

# Clear the password from memory
$pass1.Dispose()
$pass2.Dispose()

#endregion

#region ── Summary ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║                    Backup Complete                           ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  File  : " -NoNewline; Write-Host $outPath -ForegroundColor White
Write-Host "  Size  : " -NoNewline; Write-Host "$([Math]::Round($written / 1KB, 1)) KB" -ForegroundColor White
Write-Host "  Items : " -NoNewline; Write-Host "$totalItems across $totalVaults vault(s)" -ForegroundColor White
Write-Host ""
Write-Host "  IMPORTANT: Store this file on an encrypted drive (BitLocker) or" -ForegroundColor Yellow
Write-Host "             in OneDrive Personal Vault. The passphrase you entered" -ForegroundColor Yellow
Write-Host "             is required to restore — store it securely separately." -ForegroundColor Yellow
Write-Host ""

#endregion

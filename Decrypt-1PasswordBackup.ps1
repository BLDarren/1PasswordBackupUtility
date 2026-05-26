#Requires -Version 5.1
<#
.SYNOPSIS
    Decrypts a 1Password backup file (.1pbak) created by Backup-1PasswordVault.ps1.

.DESCRIPTION
    Reads an AES-256-CBC encrypted .1pbak file, prompts for the backup passphrase,
    decrypts the payload, and writes the plaintext JSON to a file for inspection
    or manual credential recovery.

    WARNING: The output JSON contains all passwords in plaintext.
    Delete it securely after use (the script will offer to do this for you).

.PARAMETER BackupFile
    Full path to the .1pbak file to decrypt.

.PARAMETER OutputPath
    Folder to write the decrypted JSON file. Defaults to the same folder as the
    backup file. The output file is named <original>_DECRYPTED.json.

.EXAMPLE
    .\Restore-1PasswordBackup.ps1 -BackupFile "E:\1PasswordBackup\2026-05-26_1Password_Backup_cordance.1pbak"

.EXAMPLE
    .\Restore-1PasswordBackup.ps1 -BackupFile "E:\1PasswordBackup\2026-05-26_1Password_Backup_cordance.1pbak" -OutputPath "C:\Temp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BackupFile,

    [Parameter()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Dot-source the crypto function from the backup script ─────────────────────
$backupScript = Join-Path $PSScriptRoot 'Backup-1PasswordVault.ps1'
if (-not (Test-Path $backupScript)) {
    Write-Error "Cannot find Backup-1PasswordVault.ps1 in the same folder as this script ($PSScriptRoot). Both files must be kept together."
    exit 1
}
# Load only the function definitions — suppress all script-level execution by
# wrapping in a scriptblock that only defines functions (the backup script's
# non-function body runs inside param() which is skipped on dot-source when
# we pass fake mandatory params... actually safest is to parse the functions out).
# Instead we redefine the decrypt function inline to avoid side-effects.

function ConvertFrom-AesEncryptedBytes {
    param(
        [byte[]]$EncryptedBytes,
        [SecureString]$Password
    )

    $bstr      = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passStr   = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $passBytes = [System.Text.Encoding]::UTF8.GetBytes($passStr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $passStr   = $null

    try {
        $ms     = New-Object System.IO.BinaryReader([System.IO.MemoryStream]::new($EncryptedBytes))
        $magic  = $ms.ReadBytes(4)
        if (-not ([System.Linq.Enumerable]::SequenceEqual($magic, [byte[]]@(0x31,0x50,0x42,0x4B)))) {
            throw "Invalid magic bytes — this is not a valid .1pbak file."
        }
        $null   = $ms.ReadBytes(4)   # format version
        $iters  = [System.BitConverter]::ToUInt32($ms.ReadBytes(4), 0)
        $salt   = $ms.ReadBytes(32)
        $iv     = $ms.ReadBytes(16)
        $cipher = $ms.ReadBytes($EncryptedBytes.Length - 60)
        $ms.Dispose()

        Write-Host "  Key derivation: PBKDF2-SHA256, $iters iterations..." -ForegroundColor DarkCyan

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

# ── Validate input file ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║           1Password Backup — Decrypt & Restore               ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host ""

if (-not (Test-Path $BackupFile -PathType Leaf)) {
    Write-Error "Backup file not found: $BackupFile"
    exit 1
}

$fileInfo = Get-Item $BackupFile
Write-Host "  Backup file : $($fileInfo.FullName)" -ForegroundColor Cyan
Write-Host "  File size   : $([Math]::Round($fileInfo.Length / 1KB, 1)) KB" -ForegroundColor Cyan
Write-Host "  Created     : $($fileInfo.CreationTime)" -ForegroundColor Cyan
Write-Host ""

# ── Resolve output path ────────────────────────────────────────────────────────

if (-not $OutputPath) {
    $OutputPath = $fileInfo.DirectoryName
}
if (-not (Test-Path $OutputPath -PathType Container)) {
    Write-Error "Output path does not exist: $OutputPath"
    exit 1
}

$outFile = Join-Path $OutputPath ($fileInfo.BaseName + '_DECRYPTED.json')

# ── Prompt for passphrase ──────────────────────────────────────────────────────

Write-Host "  Enter the passphrase you used when creating this backup." -ForegroundColor Yellow
Write-Host ""
$passphrase = Read-Host -AsSecureString "  Backup passphrase"
Write-Host ""

# ── Decrypt ────────────────────────────────────────────────────────────────────

Write-Host "  Decrypting..." -ForegroundColor Cyan
try {
    $encryptedBytes = [System.IO.File]::ReadAllBytes($BackupFile)
    $jsonText       = ConvertFrom-AesEncryptedBytes -EncryptedBytes $encryptedBytes -Password $passphrase
    $encryptedBytes = $null
}
catch {
    Write-Host ""
    Write-Host "  [FAIL] Decryption failed. Wrong passphrase, or the file is corrupt." -ForegroundColor Red
    Write-Host "         Error: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}
finally {
    $passphrase.Dispose()
}

# ── Parse and summarise ────────────────────────────────────────────────────────

$data       = $jsonText | ConvertFrom-Json
$vaultCount = $data.vaults.Count
$itemCount  = ($data.vaults | ForEach-Object { $_.items.Count } | Measure-Object -Sum).Sum

Write-Host "  [OK] Decryption successful." -ForegroundColor Green
Write-Host ""
Write-Host "  Exported by  : $($data.exportedBy)" -ForegroundColor White
Write-Host "  Account      : $($data.account)"    -ForegroundColor White
Write-Host "  Exported at  : $($data.exportedAt)" -ForegroundColor White
Write-Host "  Vaults       : $vaultCount"          -ForegroundColor White
Write-Host "  Total items  : $itemCount"            -ForegroundColor White
Write-Host ""

# Show per-vault summary
foreach ($vault in $data.vaults) {
    Write-Host ("  [{0,3} items]  {1}" -f $vault.items.Count, $vault.name) -ForegroundColor DarkCyan
}
Write-Host ""

# ── Write plaintext JSON ───────────────────────────────────────────────────────

# Pretty-print for human readability
$prettyJson = $data | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($outFile, $prettyJson, [System.Text.Encoding]::UTF8)
$jsonText   = $null
$data       = $null

Write-Host "  Decrypted JSON written to:" -ForegroundColor Yellow
Write-Host "  $outFile" -ForegroundColor White
Write-Host ""
Write-Host "  WARNING: This file contains all passwords in plaintext." -ForegroundColor Red
Write-Host "           Delete it securely when you are done." -ForegroundColor Red
Write-Host ""

# ── Offer to open the file ─────────────────────────────────────────────────────

$open = Read-Host "  Open the file in Notepad now? (Y/N)"
if ($open -match '^[Yy]') {
    Start-Process notepad.exe -ArgumentList $outFile
}

# ── Offer to securely delete after viewing ────────────────────────────────────

Write-Host ""
$delete = Read-Host "  Securely delete the decrypted JSON file when done? (Y/N)"
if ($delete -match '^[Yy]') {
    # Overwrite with random bytes before deleting to reduce forensic recoverability
    $size        = (Get-Item $outFile).Length
    $randomBytes = [byte[]]::new($size)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randomBytes)
    [System.IO.File]::WriteAllBytes($outFile, $randomBytes)
    Remove-Item $outFile -Force
    Write-Host "  [OK] Decrypted file securely deleted." -ForegroundColor Green
}
else {
    Write-Host "  [!]  Remember to delete $outFile when you are finished." -ForegroundColor Yellow
}

Write-Host ""

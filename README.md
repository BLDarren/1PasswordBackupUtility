# 1Password Vault Backup and Decrypt Utility

An offline backup toolset for 1Password accounts that use **SSO (Single Sign-On)**, such as Azure AD / Entra ID. The standard 1Password app disables the "Export" menu option for SSO accounts, but these scripts bypass that restriction by using the **1Password CLI (`op`)**, which reads items directly from the unlocked vault session.

This folder includes:

- `Backup-1PasswordVault.ps1` to create encrypted `.1pbak` backup files
- `Decrypt-1PasswordBackup.ps1` to decrypt those `.1pbak` files into JSON for inspection and recovery

---

## Problem This Solves

When 1Password is configured with SSO (e.g. Azure AD), the GUI export option is disabled by policy. If the SSO integration breaks — as can happen during an Azure AD outage or misconfiguration — you may be locked out of all your passwords with no offline backup available. This script lets you create an encrypted offline backup **while you are authenticated**, so you always have a recovery copy.

---

## Prerequisites

### 1. Install 1Password CLI

```powershell
winget install AgileBits.1Password.CLI
```

Or download manually from https://developer.1password.com/docs/cli/get-started/

Verify the install:

```powershell
op --version
```

### 2. Enable CLI Integration in the Desktop App

1. Open the **1Password desktop app** and sign in via SSO.
2. Go to **Settings > Developer**.
3. Enable **Integrate with 1Password CLI**.
4. Optionally enable **Windows Hello** for biometric unlock of CLI commands.

### 3. Approve CLI Access (First Run Only)

The first time the CLI connects to the app, you will be prompted to approve the connection in the 1Password app window. After approval, subsequent runs authenticate silently via Windows Hello or a PIN.

---

## Usage

```powershell
# Back up all accessible vaults to a BitLocker-encrypted drive
.\Backup-1PasswordVault.ps1 -DestinationPath "E:\SecureBackups"

# Back up a single named vault
.\Backup-1PasswordVault.ps1 -DestinationPath "E:\SecureBackups" -VaultName "Personal"

# Include Document/file attachment items (increases size and run time)
.\Backup-1PasswordVault.ps1 -DestinationPath "E:\SecureBackups" -IncludeDocuments

# Target a specific account when multiple accounts are added to the desktop app
.\Backup-1PasswordVault.ps1 -DestinationPath "E:\SecureBackups" -AccountShorthand "mycompany"
```

## Decrypt a Backup File

Use `Decrypt-1PasswordBackup.ps1` to decrypt a backup created by `Backup-1PasswordVault.ps1`.

```powershell
# Decrypt to JSON in the same folder as the backup file
.\Decrypt-1PasswordBackup.ps1 -BackupFile "E:\SecureBackups\2026-05-26_14-30-00_1Password_Backup_mycompany.1pbak"

# Decrypt to a specific output folder
.\Decrypt-1PasswordBackup.ps1 -BackupFile "E:\SecureBackups\2026-05-26_14-30-00_1Password_Backup_mycompany.1pbak" -OutputPath "C:\Temp"
```

What it does:

1. Prompts for the backup passphrase.
2. Decrypts the `.1pbak` file.
3. Validates JSON and prints a summary (vault count, item count, and per-vault totals).
4. Writes plaintext JSON as `<backup-name>_DECRYPTED.json`.
5. Offers to open the file and then securely delete it when done.

Important:

- `Decrypt-1PasswordBackup.ps1` does **not** restore/import data back into 1Password.
- It only decrypts the backup for viewing or manual recovery.

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-DestinationPath` | No (default: script folder) | Folder to save the encrypted `.1pbak` file |
| `-VaultName` | No | Restrict backup to one named vault; omit for all vaults |
| `-IncludeDocuments` | No | Download and embed document/file attachment items as Base64 |
| `-AccountShorthand` | No | Account short name (e.g. `mycompany` from `mycompany.1password.com`) — needed only when multiple accounts are configured |

---

## What the Script Does

```
1. Checks that op CLI is installed and on PATH
2. Validates the destination path exists
3. Calls op whoami — confirms the desktop app is unlocked and SSO session is active
4. Prompts for a backup passphrase (entered twice for confirmation)
5. Calls op vault list to enumerate all accessible vaults
6. For each vault, calls op item list then op item get --reveal --format json
   - --reveal forces concealed fields (passwords, secrets) to be included in output
7. Optionally downloads Document items via op document get
8. Serializes all data to JSON
9. Encrypts the JSON with AES-256-CBC and a PBKDF2-SHA256-derived key
10. Writes the encrypted .1pbak file
11. Self-test: decrypts the file and verifies item/vault counts
12. Clears all plaintext from memory
```

---

## Output File Format

The backup is saved as a timestamped `.1pbak` file:

```
2026-05-25_14-30-00_1Password_Backup_mycompany-1password-com.1pbak
```

### Binary File Layout

| Offset | Size | Content |
|---|---|---|
| 0 | 4 bytes | Magic: `1PBK` (0x31 0x50 0x42 0x4B) |
| 4 | 4 bytes | Format version (uint32 LE = 1) |
| 8 | 4 bytes | PBKDF2 iteration count (uint32 LE) |
| 12 | 32 bytes | PBKDF2 salt (random per backup) |
| 44 | 16 bytes | AES IV (random per backup) |
| 60 | N bytes | AES-256-CBC encrypted JSON payload (PKCS7 padded) |

### Encryption Details

- **Algorithm**: AES-256-CBC
- **Key derivation**: PBKDF2-HMAC-SHA256, 600,000 iterations (NIST recommended minimum)
- **Salt**: 32 bytes, cryptographically random, unique per backup
- **IV**: 16 bytes, cryptographically random, unique per backup
- **Plaintext**: UTF-8 encoded JSON

### Decrypting Manually

To decrypt with any standard crypto library:

```
key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, dkLen=32)
plaintext = AES-256-CBC-Decrypt(key, iv, ciphertext)
```

---

## Decrypted JSON Structure

```json
{
  "formatVersion": 1,
  "exportedAt": "2026-05-25T14:30:00.000Z",
  "exportedBy": "darren@example.com",
  "account": "mycompany.1password.com",
  "vaults": [
    {
      "id": "abc123...",
      "name": "Personal",
      "type": "PERSONAL",
      "items": [
        {
          "id": "xyz789...",
          "title": "My Login",
          "category": "LOGIN",
          "fields": [
            { "id": "username", "label": "username", "value": "darren@example.com" },
            { "id": "password", "label": "password", "type": "CONCEALED", "value": "MyActualPassword" }
          ],
          ...
        }
      ]
    }
  ]
}
```

All fields, including passwords and other concealed values, are present in plain text inside the encrypted payload.

---

## Recommended Storage Locations

The `.1pbak` file is strongly encrypted, but defence-in-depth is recommended:

| Location | Notes |
|---|---|
| **BitLocker-encrypted USB drive** | Best for air-gapped offline backup |
| **OneDrive Personal Vault** | Microsoft's extra-authentication folder; good for offsite cloud backup |
| **BitLocker-encrypted internal drive** | Acceptable if the machine itself is physically secure |

> **Do not** store the backup passphrase in the same location as the backup file. Store it separately — in a printed copy in a safe, or in a second password manager (e.g. your personal 1Password Family account).

---

## Security Considerations

- The script **never writes plaintext to disk** — serialization, encryption, and file write happen in memory.
- Sensitive byte arrays (`$passBytes`, `$plainBytes`) are zeroed with `Array.Clear()` immediately after use.
- The passphrase is stored as a `SecureString` throughout and only briefly materialized as bytes during key derivation.
- The `--reveal` flag is required to expose concealed fields; the CLI will only honour this if the desktop app session is currently unlocked.

---

## Restore / Inspection

Use `Decrypt-1PasswordBackup.ps1` for inspection and recovery drills.

Current behavior:

1. Decrypts a `.1pbak` into plaintext JSON.
2. Writes the JSON to disk for human inspection.
3. Does not push/import any data into 1Password.

If full restore-to-1Password automation is needed later, that would require a separate import script that maps JSON fields back to item templates and creates items with `op item create`.

---

## Automating Backups

The script can be run on a schedule (e.g. Task Scheduler) **only while you are actively logged in and the 1Password app is unlocked**, since it requires an active SSO session. It cannot run fully headless without a Service Account token (which requires a separate 1Password configuration outside SSO).

For a prompted scheduled task, configure the trigger to run at logon and use an `-EncryptionPassword` parameter variation, or simply run the script manually before major changes or periodically (e.g. monthly).

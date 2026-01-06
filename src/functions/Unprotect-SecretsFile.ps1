function Unprotect-SecretsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Security.SecureString]$Password,
        [string]$OutputPath,
        [switch]$RemoveEncrypted,
        [string]$LogFile
    )

    function ConvertTo-PlainText {
        param(
            [Parameter(Mandatory = $true)]
            [Security.SecureString]$SecureString
        )

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    function Write-SecretLog {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
            [string]$Level = "INFO"
        )

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message $Message -Level $Level -LogFile $LogFile
        } else {
            Write-Host "[$Level] $Message"
        }
    }

    if (-not (Test-Path $FilePath)) {
        Write-SecretLog -Message "Encrypted secrets file not found at $FilePath." -Level "WARNING"
        return
    }

    if (-not $Password) {
        $Password = Read-Host -Prompt "Enter secrets file password" -AsSecureString
    }

    $plainPassword = ConvertTo-PlainText -SecureString $Password
    if ([string]::IsNullOrWhiteSpace($plainPassword)) {
        Write-SecretLog -Message "Secrets password is empty. Skipping decryption." -Level "WARNING"
        return
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        if ($FilePath -match "\.enc$") {
            $OutputPath = $FilePath -replace "\.enc$", ""
        } else {
            $OutputPath = "$FilePath.dec"
        }
    }

    $payload = $null
    try {
        $payload = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
    } catch {
        Write-SecretLog -Message "Failed to parse encrypted payload: $_" -Level "ERROR"
        return
    }

    if (-not $payload.Salt -or -not $payload.IV -or -not $payload.CipherText) {
        Write-SecretLog -Message "Encrypted payload is missing required fields." -Level "ERROR"
        return
    }

    $iterations = 200000
    if ($payload.Iterations) {
        $iterations = [int]$payload.Iterations
    }

    $salt = $null
    $iv = $null
    $cipherBytes = $null
    $pbkdf2 = $null
    $aes = $null
    $decryptor = $null
    $memoryStream = $null
    $cryptoStream = $null

    try {
        $salt = [Convert]::FromBase64String($payload.Salt)
        $iv = [Convert]::FromBase64String($payload.IV)
        $cipherBytes = [Convert]::FromBase64String($payload.CipherText)

        $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, $iterations)
        $key = $pbkdf2.GetBytes(32)

        $aes = [Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv

        $memoryStream = New-Object IO.MemoryStream
        $decryptor = $aes.CreateDecryptor()
        $cryptoStream = New-Object Security.Cryptography.CryptoStream(
            $memoryStream,
            $decryptor,
            [Security.Cryptography.CryptoStreamMode]::Write
        )
        $cryptoStream.Write($cipherBytes, 0, $cipherBytes.Length)
        $cryptoStream.FlushFinalBlock()

        [IO.File]::WriteAllBytes($OutputPath, $memoryStream.ToArray())

        if ($RemoveEncrypted) {
            Remove-Item -Path $FilePath -Force
        }

        Write-SecretLog -Message "Decrypted secrets file saved to $OutputPath." -Level "SUCCESS"
    } catch {
        Write-SecretLog -Message "Failed to decrypt secrets file: $_" -Level "ERROR"
    } finally {
        if ($cryptoStream) { $cryptoStream.Dispose() }
        if ($decryptor) { $decryptor.Dispose() }
        if ($memoryStream) { $memoryStream.Dispose() }
        if ($aes) { $aes.Dispose() }
        if ($pbkdf2) { $pbkdf2.Dispose() }
    }
}

function Protect-SecretsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$Password,
        [string]$OutputPath,
        [int]$Iterations = 200000,
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
        Write-SecretLog -Message "Secrets file not found at $FilePath. Skipping encryption." -Level "WARNING"
        return
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = "$FilePath.enc"
    }

    $plainPassword = ConvertTo-PlainText -SecureString $Password
    if ([string]::IsNullOrWhiteSpace($plainPassword)) {
        Write-SecretLog -Message "Secrets password is empty. Skipping encryption." -Level "WARNING"
        return
    }

    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    $rng = $null
    $pbkdf2 = $null
    $aes = $null
    $encryptor = $null
    $memoryStream = $null
    $cryptoStream = $null

    try {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($salt)
        $rng.GetBytes($iv)

        $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, $Iterations)
        $key = $pbkdf2.GetBytes(32)

        $aes = [Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv

        $plaintextBytes = [IO.File]::ReadAllBytes($FilePath)
        $memoryStream = New-Object IO.MemoryStream
        $encryptor = $aes.CreateEncryptor()
        $cryptoStream = New-Object Security.Cryptography.CryptoStream(
            $memoryStream,
            $encryptor,
            [Security.Cryptography.CryptoStreamMode]::Write
        )
        $cryptoStream.Write($plaintextBytes, 0, $plaintextBytes.Length)
        $cryptoStream.FlushFinalBlock()

        $cipherBytes = $memoryStream.ToArray()
        $payload = [PSCustomObject]@{
            Version    = 1
            Algorithm  = "AES-256-CBC"
            Kdf        = "PBKDF2"
            Iterations = $Iterations
            Salt       = [Convert]::ToBase64String($salt)
            IV         = [Convert]::ToBase64String($iv)
            CipherText = [Convert]::ToBase64String($cipherBytes)
        }

        $json = $payload | ConvertTo-Json -Compress
        Set-Content -Path $OutputPath -Value $json -Encoding ASCII
        Remove-Item -Path $FilePath -Force

        Write-SecretLog -Message "Encrypted secrets file saved to $OutputPath and removed plaintext CSV." -Level "SUCCESS"
    } catch {
        Write-SecretLog -Message "Failed to encrypt secrets file: $_" -Level "ERROR"
    } finally {
        if ($cryptoStream) { $cryptoStream.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }
        if ($memoryStream) { $memoryStream.Dispose() }
        if ($aes) { $aes.Dispose() }
        if ($pbkdf2) { $pbkdf2.Dispose() }
        if ($rng) { $rng.Dispose() }
    }
}

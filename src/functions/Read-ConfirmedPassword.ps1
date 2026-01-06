function Read-ConfirmedPassword {
    [CmdletBinding()]
    param(
        [string]$Prompt = "Enter secrets file password",
        [string]$ConfirmPrompt = "Confirm secrets file password",
        [int]$MinLength = 8
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

    while ($true) {
        $first = Read-Host -Prompt $Prompt -AsSecureString
        $second = Read-Host -Prompt $ConfirmPrompt -AsSecureString

        $firstPlain = ConvertTo-PlainText -SecureString $first
        $secondPlain = ConvertTo-PlainText -SecureString $second

        if ([string]::IsNullOrWhiteSpace($firstPlain)) {
            Write-Warning "Password cannot be empty."
            continue
        }

        if ($firstPlain.Length -lt $MinLength) {
            Write-Warning "Password must be at least $MinLength characters."
            continue
        }

        if ($firstPlain -ne $secondPlain) {
            Write-Warning "Passwords do not match. Try again."
            continue
        }

        return $first
    }
}

param(
    [Parameter(Mandatory = $true)]
    [Alias("FilePath")]
    [string]$EncryptedPath,
    [string]$OutputPath,
    [switch]$RemoveEncrypted
)

$ScriptRoot = $PSScriptRoot
. "$ScriptRoot/src/functions/Unprotect-SecretsFile.ps1"

Unprotect-SecretsFile -FilePath $EncryptedPath -OutputPath $OutputPath -RemoveEncrypted:$RemoveEncrypted

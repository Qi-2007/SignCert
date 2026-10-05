param([switch]$RecoverTokens)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $diagnosisMasterSecure = Read-Host '输入原 PKI_MASTER_KEY（不会显示）' -AsSecureString
    if (-not $RecoverTokens) {
        $diagnosisTokenSecure = Read-Host '输入页面报错时使用的管理令牌（不会显示）' -AsSecureString
    }
    $diagnosisInput = @{
        master = [System.Net.NetworkCredential]::new('', $diagnosisMasterSecure).Password
        token = if ($RecoverTokens) { '' } else { [System.Net.NetworkCredential]::new('', $diagnosisTokenSecure).Password }
    }
    if ($RecoverTokens) {
        $diagnosisInput | ConvertTo-Json -Compress | pnpm exec tsx scripts/diagnose-auth.ts --recover-tokens
    } else {
        $diagnosisInput | ConvertTo-Json -Compress | pnpm exec tsx scripts/diagnose-auth.ts
    }
    $diagnosisExitCode = $LASTEXITCODE
} finally {
    $diagnosisInput = $null
    $diagnosisMasterSecure = $null
    $diagnosisTokenSecure = $null
    Pop-Location
}
exit $diagnosisExitCode

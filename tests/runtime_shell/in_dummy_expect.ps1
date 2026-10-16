. "$PSScriptRoot/common.ps1"

try {
    Assert-RuntimeEnvironment
    $exitCode = Invoke-FluentBit (Get-RuntimeConfigPath "in_dummy_expect.conf")
    if ($exitCode -ne 0) {
        throw "Fluent Bit exited with code $exitCode"
    }
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}

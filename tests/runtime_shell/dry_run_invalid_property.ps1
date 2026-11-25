. "$PSScriptRoot/common.ps1"

try {
    Assert-RuntimeEnvironment
    $configPath = Get-RuntimeConfigPath "dry_run_invalid_property.yaml"

    Write-Host "Running Fluent Bit with --dry-run and invalid property config..."
    $output = & $env:FLB_BIN --dry-run -c $configPath 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    Write-Host $output

    if ($exitCode -eq 0) {
        throw "Fluent Bit --dry-run unexpectedly succeeded"
    }
    if (-not $output.Contains(
            "unknown configuration property 'invalid_property_that_does_not_exist'")) {
        throw "Unknown property error was not reported"
    }
    if (-not $output.Contains("check properties for input plugins is failed")) {
        throw "Input plugin validation error was not reported"
    }

    Write-Host "Test passed: Fluent Bit detected the invalid property"
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}

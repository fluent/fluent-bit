. "$PSScriptRoot/common.ps1"

try {
    Assert-RuntimeEnvironment
    $configPath = Get-RuntimeConfigPath "processor_invalid.yaml"

    Write-Host "Running Fluent Bit with invalid processor YAML config..."
    $output = & $env:FLB_BIN -c $configPath -o stdout 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    Write-Host $output

    $invalidProcessor = $output.Contains(
        "error creating processor 'non_existent_processor': " +
        "plugin doesn't exist or failed to initialize")
    $failedInitialization = $output.Contains("error initializing processor")

    if ($exitCode -eq 0) {
        throw "Fluent Bit unexpectedly accepted an invalid processor"
    }
    if (-not ($invalidProcessor -or $failedInitialization)) {
        throw "Invalid processor error was not reported"
    }

    Write-Host "Test passed: Fluent Bit rejected the invalid processor"
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}

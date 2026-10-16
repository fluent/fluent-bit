. "$PSScriptRoot/common.ps1"

function Test-CalyptiaFleetFormat
{
    param(
        [Parameter(Mandatory = $true)][string] $Format,
        [Parameter(Mandatory = $true)][bool] $ExpectYaml
    )

    $process = $null
    $env:CALYPTIA_FLEET_FORMAT = $Format
    if (Test-Path -LiteralPath $env:CALYPTIA_FLEET_DIR) {
        Remove-Item -LiteralPath $env:CALYPTIA_FLEET_DIR -Recurse -Force
    }
    [void] (New-Item -ItemType Directory -Path $env:CALYPTIA_FLEET_DIR)

    $config = Get-RuntimeConfigPath "custom_calyptia_fleet.conf"
    $exitCode = Invoke-FluentBit $config @("--dry-run")
    if ($exitCode -ne 0) {
        throw "Calyptia fleet dry run failed with code $exitCode"
    }

    try {
        $process = Start-FluentBit $config
        Start-Sleep -Seconds 30
        if ($process.HasExited -and $process.ExitCode -ne 0) {
            throw "Fluent Bit exited with code $($process.ExitCode)"
        }

        $yamlFiles = @(Get-ChildItem -LiteralPath $env:CALYPTIA_FLEET_DIR `
            -Filter "*.yaml" -File -Recurse -ErrorAction SilentlyContinue)
        if ($ExpectYaml -and $yamlFiles.Count -eq 0) {
            throw "No YAML fleet configuration files were found"
        }
        if (-not $ExpectYaml -and $yamlFiles.Count -ne 0) {
            throw "YAML fleet configuration files were unexpectedly found"
        }

        foreach ($file in $yamlFiles) {
            Get-Content -LiteralPath $file.FullName | Out-Host
        }
    }
    finally {
        Stop-FluentBit $process
    }
}

$tempDirectory = $null

try {
    Assert-RuntimeEnvironment
    if ([string]::IsNullOrWhiteSpace($env:CALYPTIA_FLEET_TOKEN)) {
        Write-Host "SKIP: CALYPTIA_FLEET_TOKEN is not set"
        exit 0
    }

    if ([string]::IsNullOrWhiteSpace($env:CALYPTIA_FLEET_DIR)) {
        $tempDirectory = New-RuntimeTempDirectory "custom-calyptia"
        $env:CALYPTIA_FLEET_DIR = Join-Path $tempDirectory "fleet-test"
    }

    Test-CalyptiaFleetFormat "off" $true
    Test-CalyptiaFleetFormat "on" $false
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($null -ne $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

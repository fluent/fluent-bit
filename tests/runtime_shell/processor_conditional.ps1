. "$PSScriptRoot/common.ps1"

function Invoke-ConditionalProcessor
{
    param(
        [Parameter(Mandatory = $true)][string] $ConfigPath,
        [Parameter(Mandatory = $true)][string] $OutputPath,
        [Parameter(Mandatory = $true)][string] $ErrorPath
    )

    $process = $null
    try {
        $process = Start-FluentBit $ConfigPath @("-o", "stdout") $OutputPath $ErrorPath
        Start-Sleep -Seconds 5
        if ($process.HasExited -and $process.ExitCode -ne 0) {
            throw "Fluent Bit exited with code $($process.ExitCode)"
        }
    }
    finally {
        Stop-FluentBit $process
    }

    $output = ""
    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
        $output += Get-Content -LiteralPath $OutputPath -Raw
    }
    if (Test-Path -LiteralPath $ErrorPath -PathType Leaf) {
        $output += Get-Content -LiteralPath $ErrorPath -Raw
    }
    return $output
}

$tempDirectory = $null

try {
    Assert-RuntimeEnvironment
    $tempDirectory = New-RuntimeTempDirectory "processor-conditional"
    $conditionalConfigPath = Get-RuntimeConfigPath "processor_conditional.yaml"

    $conditionalOutput = Invoke-ConditionalProcessor `
        $conditionalConfigPath `
        (Join-Path $tempDirectory "processor_conditional.stdout") `
        (Join-Path $tempDirectory "processor_conditional.stderr")
    Write-Host $conditionalOutput

    if (-not $conditionalOutput.Contains("modified_if_get")) {
        throw "GET condition was not applied"
    }
    if ($conditionalOutput.Contains("modified_if_post")) {
        throw "POST condition was unexpectedly applied"
    }

    $grepConfigPath = Get-RuntimeConfigPath "processor_conditional_grep.yaml"

    $grepOutput = Invoke-ConditionalProcessor `
        $grepConfigPath `
        (Join-Path $tempDirectory "processor_conditional_grep.stdout") `
        (Join-Path $tempDirectory "processor_conditional_grep.stderr")
    Write-Host $grepOutput

    if (-not $grepOutput.Contains('"endpoint"=>"localhost"')) {
        throw "localhost record was not emitted"
    }
    if (-not $grepOutput.Contains('"endpoint"=>"localhost2"')) {
        throw "localhost2 record was not emitted"
    }
    if ($grepOutput.Contains('"endpoint"=>"farhost"')) {
        throw "farhost record was unexpectedly emitted"
    }

    Write-Host "Test passed: conditional processors selected the expected records"
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

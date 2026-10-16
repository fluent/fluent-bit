Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-RuntimeEnvironment
{
    foreach ($name in @("FLB_ROOT", "FLB_RUNTIME_SHELL_PATH",
                        "FLB_RUNTIME_SHELL_CONF", "FLB_BIN", "FLB_BUILD")) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Required environment variable $name is not set"
        }
    }

    if (-not (Test-Path -LiteralPath $env:FLB_BIN -PathType Leaf)) {
        throw "Fluent Bit executable was not found at $env:FLB_BIN"
    }
}

function Get-RuntimeConfigPath
{
    param([Parameter(Mandatory = $true)][string] $Name)

    return Join-Path $env:FLB_RUNTIME_SHELL_CONF $Name
}

function New-RuntimeTempDirectory
{
    param([Parameter(Mandatory = $true)][string] $Name)

    $directory = Join-Path ([IO.Path]::GetTempPath()) (
        "fluent-bit-runtime-shell-{0}-{1}" -f $Name, [guid]::NewGuid())
    [void] (New-Item -ItemType Directory -Path $directory)
    return $directory
}

function Start-FluentBit
{
    param(
        [Parameter(Mandatory = $true)][string] $ConfigPath,
        [string[]] $AdditionalArguments = @(),
        [string] $StandardOutputPath,
        [string] $StandardErrorPath
    )

    $arguments = @("-c", ('"{0}"' -f $ConfigPath)) + $AdditionalArguments
    $parameters = @{
        FilePath = $env:FLB_BIN
        ArgumentList = $arguments
        NoNewWindow = $true
        PassThru = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($StandardOutputPath)) {
        $parameters.RedirectStandardOutput = $StandardOutputPath
    }
    if (-not [string]::IsNullOrWhiteSpace($StandardErrorPath)) {
        $parameters.RedirectStandardError = $StandardErrorPath
    }

    return Start-Process @parameters
}

function Stop-FluentBit
{
    param([System.Diagnostics.Process] $Process)

    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force
        [void] $Process.WaitForExit(5000)
    }
}

function Wait-ForFile
{
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][System.Diagnostics.Process] $Process,
        [int] $TimeoutSeconds = 15
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return
        }
        if ($Process.HasExited) {
            throw "Fluent Bit exited before creating $Path (code $($Process.ExitCode))"
        }
        Start-Sleep -Milliseconds 100
    }

    throw "Timed out waiting for Fluent Bit to create $Path"
}

function Wait-FluentBitExit
{
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process] $Process,
        [int] $TimeoutSeconds = 15
    )

    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-FluentBit $Process
        throw "Timed out waiting for Fluent Bit to exit"
    }
    if ($Process.ExitCode -ne 0) {
        throw "Fluent Bit exited with code $($Process.ExitCode)"
    }
}

function Invoke-FluentBit
{
    param(
        [Parameter(Mandatory = $true)][string] $ConfigPath,
        [string[]] $AdditionalArguments = @()
    )

    & $env:FLB_BIN -c $ConfigPath @AdditionalArguments | Out-Host
    $exitCode = $LASTEXITCODE
    return $exitCode
}

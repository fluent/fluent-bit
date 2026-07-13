. "$PSScriptRoot/common.ps1"

$tempDirectory = $null

try {
    Assert-RuntimeEnvironment
    $tempDirectory = New-RuntimeTempDirectory "in-tail-expect"
    $targetFile = Join-Path $tempDirectory "flb_tail_expect_1.log"
    $excludedFile = Join-Path $tempDirectory "flb_tail_expect_2.log"

    $env:TAIL_TEST_GLOB = Join-Path $tempDirectory "flb_tail_expect_*.log"
    $env:TAIL_TEST_EXCLUDE = Join-Path $tempDirectory "flb_*2.log"
    $env:TAIL_TEST_FILE = $targetFile
    $env:TAIL_TEST_DB = Join-Path $tempDirectory "flb_tail_expect.db"

    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText(
        $targetFile, "{`"key`": `"val`"}`r`n", $encoding)
    [IO.File]::WriteAllText(
        $excludedFile, "{`"nokey`": `"`"}`r`n", $encoding)

    $config = Get-RuntimeConfigPath "in_tail_expect.conf"
    $exitCode = Invoke-FluentBit $config
    if ($exitCode -ne 0) {
        throw "Fluent Bit exited with code $exitCode"
    }
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

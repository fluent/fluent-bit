. "$PSScriptRoot/common.ps1"

$process = $null
$tempDirectory = $null
$client = $null

try {
    Assert-RuntimeEnvironment
    $tempDirectory = New-RuntimeTempDirectory "syslog-tcp"
    $signalFile = Join-Path $tempDirectory "signal.log"
    $env:SIGNAL_FILE_PATH = $signalFile
    $env:LISTENER_HOST = "127.0.0.1"
    $env:LISTENER_PORT = "50001"

    $config = Get-RuntimeConfigPath "in_syslog_tcp_plaintext_expect.conf"
    $process = Start-FluentBit $config
    Wait-ForFile $signalFile $process

    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect($env:LISTENER_HOST, [int] $env:LISTENER_PORT)
    $stream = $client.GetStream()
    $payload = [Text.Encoding]::UTF8.GetBytes(
        "<13>1 1970-01-01T00:00:00.000000+00:00 testhost testuser - - [] Hello!`n")
    $stream.Write($payload, 0, $payload.Length)
    $stream.Flush()
    $client.Close()
    $client = $null

    Wait-FluentBitExit $process
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($null -ne $client) {
        $client.Dispose()
    }
    Stop-FluentBit $process
    if ($null -ne $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

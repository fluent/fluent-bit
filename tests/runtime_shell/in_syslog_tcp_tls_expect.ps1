. "$PSScriptRoot/common.ps1"

$process = $null
$tempDirectory = $null
$client = $null
$tlsStream = $null

try {
    Assert-RuntimeEnvironment
    $tempDirectory = New-RuntimeTempDirectory "syslog-tcp-tls"
    $signalFile = Join-Path $tempDirectory "signal.log"
    $env:SIGNAL_FILE_PATH = $signalFile
    $env:LISTENER_VHOST = "leo.vcap.me"
    $env:LISTENER_HOST = "127.0.0.1"
    $env:LISTENER_PORT = "50002"

    $config = Get-RuntimeConfigPath "in_syslog_tcp_tls_expect.conf"
    $process = Start-FluentBit $config
    Wait-ForFile $signalFile $process

    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect($env:LISTENER_HOST, [int] $env:LISTENER_PORT)
    $validationCallback = [Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        return $true
    }
    $tlsStream = [Net.Security.SslStream]::new(
        $client.GetStream(), $false, $validationCallback)
    $tlsOptions = [Net.Security.SslClientAuthenticationOptions]::new()
    $tlsOptions.TargetHost = $env:LISTENER_VHOST
    $tlsOptions.EnabledSslProtocols = [Security.Authentication.SslProtocols]::Tls12
    $tlsOptions.CertificateRevocationCheckMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $tlsStream.AuthenticateAsClient($tlsOptions)
    $payload = [Text.Encoding]::UTF8.GetBytes(
        "<13>1 1970-01-01T00:00:00.000000+00:00 testhost testuser - - [] Hello!`n")
    $tlsStream.Write($payload, 0, $payload.Length)
    $tlsStream.Flush()
    $tlsStream.Close()
    $tlsStream = $null
    $client.Close()
    $client = $null

    Wait-FluentBitExit $process
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.ToString())"
    exit 1
}
finally {
    if ($null -ne $tlsStream) {
        $tlsStream.Dispose()
    }
    if ($null -ne $client) {
        $client.Dispose()
    }
    Stop-FluentBit $process
    if ($null -ne $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

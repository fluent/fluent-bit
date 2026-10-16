. "$PSScriptRoot/common.ps1"

Add-Type -TypeDefinition @'
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class RuntimeShellCertificateValidator
{
    public static bool ValidateHttp(
        HttpRequestMessage request,
        X509Certificate2 certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
    {
        return true;
    }
}
'@

$process = $null
$tempDirectory = $null
$client = $null
$handler = $null
$content = $null

try {
    Assert-RuntimeEnvironment
    $tempDirectory = New-RuntimeTempDirectory "http-tls"
    $signalFile = Join-Path $tempDirectory "signal.log"
    $env:SIGNAL_FILE_PATH = $signalFile
    $env:LISTENER_VHOST = "leo.vcap.me"
    $env:LISTENER_HOST = "127.0.0.1"
    $env:LISTENER_PORT = "50000"

    $config = Get-RuntimeConfigPath "in_http_tls_expect.conf"
    $process = Start-FluentBit $config
    Wait-ForFile $signalFile $process

    $handler = [Net.Http.HttpClientHandler]::new()
    $validatorType = [Func[Net.Http.HttpRequestMessage,
        Security.Cryptography.X509Certificates.X509Certificate2,
        Security.Cryptography.X509Certificates.X509Chain,
        Net.Security.SslPolicyErrors, bool]]
    $validatorMethod = [RuntimeShellCertificateValidator].GetMethod("ValidateHttp")
    $handler.ServerCertificateCustomValidationCallback =
        $validatorMethod.CreateDelegate($validatorType)
    $handler.SslProtocols = [Security.Authentication.SslProtocols]::Tls12
    $client = [Net.Http.HttpClient]::new($handler)
    $content = [Net.Http.StringContent]::new(
        '{"message":"Hello!"}', [Text.Encoding]::UTF8, "application/json")
    $uri = "https://$($env:LISTENER_HOST):$($env:LISTENER_PORT)"
    $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
    if (-not $response.IsSuccessStatusCode) {
        throw "HTTP input returned status $([int] $response.StatusCode)"
    }

    Wait-FluentBitExit $process
    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.ToString())"
    exit 1
}
finally {
    if ($null -ne $content) {
        $content.Dispose()
    }
    if ($null -ne $client) {
        $client.Dispose()
    }
    if ($null -ne $handler) {
        $handler.Dispose()
    }
    Stop-FluentBit $process
    if ($null -ne $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

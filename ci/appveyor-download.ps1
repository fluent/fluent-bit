param (
  [Parameter(Position=0)]
  [string] $version,

  [ValidateSet('win32', 'x64')]
  [string] $platform,

  [ValidateSet('exe', 'zip')]
  [string] $filetype
)

# URL Paths
$GITHUB_URL = "https://api.github.com/repos/fluent/fluent-bit/statuses/{0}"
$APPVEYOR_JOBS = "https://ci.appveyor.com/api/projects/fluent/{0}/builds/{1}"
$APPVEYOR_LIST = "https://ci.appveyor.com/api/buildjobs/{0}/artifacts"
$APPVEYOR_FILE = "https://ci.appveyor.com/api/buildjobs/{0}/artifacts/{1}"

# Utility functions
function Usage
{
  $usage = @"

  Usage: appveyor-download [version] [filters]

    version - the fluent-bit version to download (eg. v1.3.3)

  Filters:

    platform - win32 or x64
    filetype - exe or zip

  Examples:

    # Download all fluent-bit artifacts
    appveyor-download.ps1 v1.3.3

    # Download only x64 fluent-bit artifacts (exe and zip)
    appveyor-download.ps1 v1.3.3 -platform x64

    # Download only x64 zip fluent-bit artifacts
    appveyor-download.ps1 v1.3.3 -platform x64 -filetype zip

"@
  Write-Host $usage
  exit
}
function Log-Message
{
  param ( $message )
  $now = $(Get-Date((Get-Date).ToUniversalTime()) -UFormat '%Y-%m-%dT%H:%M:%SZ')
  Write-Host $("[{0}] {1}" -f $now, $message)
}
function Test-EmptyStringValue
{
  param ( $str )
  return [string]::IsNullOrEmpty($str) -or $str.Trim().length -eq 0
}

function Get-WebApiPayload
{
  param ( $url )

  Log-Message $("Request: {0}" -f $url)
  $wc = New-Object System.Net.WebClient
  $wc.Headers.Add("User-Agent", "fluent-bit-builder")
  $payload = $wc.DownloadString($url)
  return $payload
}
function Get-File
{
  param ( $url, $filename, $size )

  $filename = [System.IO.Path]::GetFileName($filename)
  Log-Message $("* {0} ({1} bytes)" -f $filename, $size)

  $state = $ProgressPreference
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -URI $url -OutFile $filename
  $ProgressPreference = $state
}

# GitHub and Appveyor functions
function Get-Build
{
  param ( $version )

  $builds = Get-WebApiPayload($GITHUB_URL -f $version) | ConvertFrom-Json
  foreach ($build in $builds) {
    if ($build.description -eq "AppVeyor build succeeded") { $buildUrl = $build.target_url; break }
  }
  if (Test-EmptyStringValue($buildUrl)) { Log-Message $("No AppVeyor build found: {0}" -f $builds); exit }

  $tokens = $buildUrl.Split('/')
  return @{
    ProjectId = $tokens[-3]
    BuildId = $tokens[-1]
  }
}

function Get-Jobs
{
  param ( $projectId, $buildId )

  $url = $APPVEYOR_JOBS -f $projectId, $buildId
  $jobs = (Get-WebApiPayload($url) | ConvertFrom-Json).build.jobs
  if (!(Test-EmptyStringValue($platform))) { $jobs = $jobs | Where-Object { $_.name.ToLower() -eq "platform: $platform" } }
  return $jobs | Select-Object jobId

}

function Get-Artifacts
{
  param ( $jobId )

  $url = $APPVEYOR_LIST -f $jobId
  $artifacts = Get-WebApiPayload($url) | ConvertFrom-Json
  if (!(Test-EmptyStringValue($filetype))) { $artifacts = $artifacts | Where-Object { $_.fileName.endswith($filetype) } }
  return $artifacts | Select-Object filename, size
}

function Get-Artifact
{
  param ( $jobId, $filename, $size )

  $url = $APPVEYOR_FILE -f $jobId, $filename
  Get-File $url $filename $size
}

# Main

if (Test-EmptyStringValue($version)) { Usage }

$build = Get-Build $version
foreach ($job in Get-Jobs $build.ProjectId $build.BuildId) {
  foreach ($artifacts in Get-Artifacts $job.jobId) {
    Get-Artifact $job.jobId $artifacts.filename $artifacts.size
  }
}


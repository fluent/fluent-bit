# Taken from https://github.com/appveyor/website/blob/master/src/docs/api/samples/download-artifacts-advanced-ps.md
function Get-AppVeyorArtifacts
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        #The name of the account you wish to download artifacts from
        [parameter(Mandatory = $true)]
        [string]$Account,
        #The name of the project you wish to download artifacts from
        [parameter(Mandatory = $true)]
        [string]$Project,
        #Where to save the downloaded artifacts. Defaults to current directory.
        [alias("DownloadDirectory")][string]$Path = '.',
        [string]$Token,
        #Filter to a specific branch or project directory. You can specify Branch as either branch name ("master") or build version ("0.1.29")
        [string]$Branch,
        #If you have multiple build jobs, specify which job you wish to retrieve the artifacts from
        [string]$JobName,
        #Download all files into a single directory, do not preserve any hierarchy that might exist in the artifacts
        [switch]$Flat,
        [string]$Proxy,
        [switch]$ProxyUseDefaultCredentials,
        #URL of Appveyor API. You normally shouldn't need to change this.
        $apiUrl = 'https://ci.appveyor.com/api'
    )

    $headers = @{
        'Content-type' = 'application/json'
    }

    if ($Token) {$headers.'Authorization' = "Bearer $token"}

    # Prepare proxy args to splat to Invoke-RestMethod
    $proxyArgs = @{}
    if (-not [string]::IsNullOrEmpty($proxy)) {
        $proxyArgs.Add('Proxy', $proxy)
    }
    if ($proxyUseDefaultCredentials.IsPresent) {
        $proxyArgs.Add('ProxyUseDefaultCredentials', $proxyUseDefaultCredentials)
    }

    $errorActionPreference = 'Stop'
    $projectURI = "$apiUrl/projects/$account/$project"
    if ($Branch) {$projectURI = $projectURI + "/branch/$Branch"}

    $projectObject = Invoke-RestMethod -Method Get -Uri $projectURI `
                                       -Headers $headers @proxyArgs

    if (-not $projectObject.build.jobs) {throw "No jobs found for this project or the project and/or account name was incorrectly specified"}

    if (($projectObject.build.jobs.count -gt 1) -and -not $jobName) {
        throw "Multiple Jobs found for the latest build. Please specify the -JobName paramter to select which job you want the artifacts for"
    }

    if ($JobName) {
        $jobid = ($projectObject.build.jobs | Where-Object name -eq "$JobName" | Select-Object -first 1).jobid
        if (-not $jobId) {throw "Unable to find a job named $JobName within the latest specified build. Did you spell it correctly?"}
    } else {
        $jobid = $projectObject.build.jobs[0].jobid
    }

    $artifacts = Invoke-RestMethod -Method Get -Uri "$apiUrl/buildjobs/$jobId/artifacts" `
                                   -Headers $headers @proxyArgs
    $artifacts `
    | ? { $psCmdlet.ShouldProcess($_.fileName) } `
    | % {

        $type = $_.type

        $localArtifactPath = $_.fileName -split '/' | % { [Uri]::UnescapeDataString($_) }
        if ($flat.IsPresent) {
            $localArtifactPath = ($localArtifactPath | select -Last 1)
        } else {
            $localArtifactPath = $localArtifactPath -join [IO.Path]::DirectorySeparatorChar
        }
        $localArtifactPath = Join-Path $path $localArtifactPath

        $artifactUrl = "$apiUrl/buildjobs/$jobId/artifacts/$($_.fileName)"
        Write-Verbose "Downloading $artifactUrl to $localArtifactPath"

        Invoke-RestMethod -Method Get -Uri $artifactUrl -OutFile $localArtifactPath -Headers $headers @proxyArgs

        New-Object PSObject -Property @{
            'Source' = $artifactUrl
            'Type'   = $type
            'Target' = $localArtifactPath
        }
    }
}
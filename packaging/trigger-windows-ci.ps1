# Trigger the workflow to test the build

if (!$env:APPVEYOR_REPO_COMMIT) {
    $env:APPVEYOR_REPO_COMMIT="$(git log -1 --pretty="%H")"
}

$COMMIT_SUBJECT="$(git log -1 "$env:APPVEYOR_REPO_COMMIT" --pretty="%s")" -replace "`"", "'"

$COMMIT_MESSAGE=(git log -1 "$env:APPVEYOR_REPO_COMMIT" --pretty="%b") -replace "`"", "'" | Out-String | ConvertTo-Json
# Remove Starting and Ending double quotes by ConvertTo-Json
$COMMIT_MESSAGE = $COMMIT_MESSAGE.Substring(1, $COMMIT_MESSAGE.Length-2)

$BUILD_VERSION = [uri]::EscapeDataString($env:APPVEYOR_BUILD_VERSION)

# TODO: change to master branch for ref before merge
$WEBHOOK_DATA="{
    ""ref"": ""4635_windows_smoke_test"",
    ""inputs"": {
        ""job-number"": ""$env:APPVEYOR_JOB_NUMBER"",
        ""build-number"": ""$env:APPVEYOR_BUILD_NUMBER""
        ""url"": ""https://ci.appveyor.com/project/$env:APPVEYOR_ACCOUNT_NAME/$env:APPVEYOR_PROJECT_SLUG/build/$BUILD_VERSION"",
        ""title"": ""$COMMIT_SUBJECT"",
        ""description"": ""$COMMIT_MESSAGE "",
        ""commit"": ""$env:APPVEYOR_REPO_COMMIT"",
        ""branch"": ""$env:APPVEYOR_REPO_BRANCH"",
        ""pull-request"": ""$env:APPVEYOR_PULL_REQUEST_NUMBER"",
        ""pull-request-title"": ""$env:APPVEYOR_PULL_REQUEST_TITLE""
    }
}"

Invoke-RestMethod -Uri "https://api.github.com/repos/octocat/hello-world/actions/workflows/windows-ci.yaml/dispatches" `
    -Method "POST" -UserAgent "AppVeyor-Webhook" `
    -ContentType "application/json" -H "Accept: application/vnd.github.v3+json" \`
    -Body $WEBHOOK_DATA

param(
    [string]$config='Release',
    [string]$platform='x64',
    [string]$toolset='v142'
)

$msbuild = (& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe)

echo "Using msbuild $msbuild"

echo "Cleaning $config $platform $toolset"
& $msbuild win32\librdkafka.sln /p:Configuration=$config /p:Platform=$platform /p:PlatformToolset=$toolset /target:Clean

echo "Building $config $platform $toolset"
& $msbuild win32\librdkafka.sln /p:Configuration=$config /p:Platform=$platform /p:PlatformToolset=$toolset
if ($LASTEXITCODE -ne 0) {
    Write-Error "msbuild failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

cd tests
$env:CI = "true";
$env:TEST_CONSUMER_GROUP_PROTOCOL = "classic";
& ..\win32\outdir\$toolset\$platform\Release\tests.exe -l -Q
if ($LASTEXITCODE -ne 0) {
    Write-Error "Classic group test failed with exit code $LASTEXITCODE"
    cd ..
    exit $LASTEXITCODE
}

# Skip tests needing special limits
$TESTS_WITH_INCREASED_NLIMIT = "0153"
$env:TESTS_SKIP = $TESTS_WITH_INCREASED_NLIMIT;
$env:TEST_CONSUMER_GROUP_PROTOCOL = "consumer";
& ..\win32\outdir\$toolset\$platform\Release\tests.exe -l -Q
if ($LASTEXITCODE -ne 0) {
    Write-Error "Consumer group test failed with exit code $LASTEXITCODE"
    cd ..
    exit $LASTEXITCODE
}
# Now run only those tests with different limits

# Tests needing increased number of file descriptors
$msvcrtCheck = Add-Type -Member '[DllImport("msvcrt.dll")] public static extern int _getmaxstdio();' -Name "CheckValue" -PassThru
$msvcrtSet = Add-Type -Member '[DllImport("msvcrt.dll")] public static extern int _setmaxstdio(int n);' -Name "SetValue" -PassThru
$originalLimit = $msvcrtCheck::_getmaxstdio()
$msvcrtSet::_setmaxstdio(2048)
$env:TESTS_SKIP = "";
$env:TESTS = $TESTS_WITH_INCREASED_NLIMIT;
& ..\win32\outdir\$toolset\$platform\Release\tests.exe -l -Q
if ($LASTEXITCODE -ne 0) {
    Write-Error "Consumer group test 0153 failed with exit code $LASTEXITCODE"
    cd ..
    exit $LASTEXITCODE
}
$msvcrtSet::_setmaxstdio($originalLimit)

cd ..

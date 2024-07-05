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

# Set up vcpkg and install required packages.
$version = "2026.04.27"
$vpkgHash=(Get-FileHash ".\librdkafka\vcpkg.json").Hash
$cacheKey = "vcpkg-$version-$Env:triplet-$vpkgHash-$Env:CACHE_TAG"
$librdkafkaPath = ".\librdkafka";

try {
    cache restore $cacheKey
} catch {
    echo "cache command not found"
}
if (!(Test-Path -Path vcpkg/.git)) {
    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    git checkout $version
    .\bootstrap-vcpkg.bat
    cd ..
    cd librdkafka
    ..\vcpkg\vcpkg integrate install
    # Install required packages.
    ..\vcpkg\vcpkg --feature-flags=versions install --triplet $Env:triplet
    cd ..
    try {
        cache store $cacheKey .\vcpkg
    } catch {
        echo "cache command not found"
    }
} else {
    cd librdkafka
    ..\vcpkg\vcpkg integrate install
    cd ..
    echo "Using previously installed vcpkg"
}


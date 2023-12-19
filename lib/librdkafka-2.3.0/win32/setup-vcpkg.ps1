# Set up vcpkg and install required packages.

if (!(Test-Path -Path vcpkg/.git)) {
    git clone https://github.com/Microsoft/vcpkg.git
}

cd vcpkg
# latest version is having an issue while doing vcpkg integrate install
git checkout 328bd79eb8340b8958f567aaf5f8ffb81056cd36
cd ..

.\vcpkg\bootstrap-vcpkg.bat


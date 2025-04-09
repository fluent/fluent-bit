# Set up vcpkg and install required packages.

if (!(Test-Path -Path vcpkg/.git)) {
    git clone https://github.com/Microsoft/vcpkg.git
}

cd vcpkg
git checkout 2024.09.30
cd ..

.\vcpkg\bootstrap-vcpkg.bat


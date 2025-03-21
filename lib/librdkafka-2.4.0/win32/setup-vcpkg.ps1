# Set up vcpkg and install required packages.

if (!(Test-Path -Path vcpkg/.git)) {
    git clone https://github.com/Microsoft/vcpkg.git
}

cd vcpkg
git checkout 2023.11.20
cd ..

.\vcpkg\bootstrap-vcpkg.bat


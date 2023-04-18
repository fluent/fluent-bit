# Install (if necessary) and set up msys2.


$url="https://github.com/msys2/msys2-installer/releases/download/2022-10-28/msys2-base-x86_64-20221028.sfx.exe"
$sha256="e365b79b4b30b6f4baf34bd93f3d2a41c0a92801c7a96d79cddbfca1090a0554"


if (!(Test-Path -Path "c:\msys64\usr\bin\bash.exe")) {
    echo "Downloading and installing msys2 to c:\msys64"

    (New-Object System.Net.WebClient).DownloadFile($url, './msys2-installer.exe')

    # Verify checksum
    (Get-FileHash -Algorithm "SHA256" .\msys2-installer.exe).hash -eq $sha256

    # Install msys2
    .\msys2-installer.exe -y -oc:\

    Remove-Item msys2-installer.exe

    # Set up msys2 the first time
    echo "Setting up msys"
    c:\msys64\usr\bin\bash -lc ' '

} else {
    echo "Using previously installed msys2"
}

# Update packages
echo "Updating msys2 packages"
c:\msys64\usr\bin\bash -lc "pacman --noconfirm -Syuu --overwrite '*'"

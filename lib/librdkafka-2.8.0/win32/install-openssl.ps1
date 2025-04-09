$OpenSSLVersion = "1_1_1k"
$OpenSSLExe = "OpenSSL-$OpenSSLVersion.exe"

if (!(Test-Path("C:\OpenSSL-Win32"))) {
   instDir = "C:\OpenSSL-Win32"
   $exeFull = "Win32$OpenSSLExe"
   $exePath = "$($env:USERPROFILE)\$exeFull"

   Write-Host "Downloading and installing OpenSSL v1.1 32-bit ..." -ForegroundColor Cyan
   (New-Object Net.WebClient).DownloadFile('https://slproweb.com/download/$exeFull', $exePath)

   Write-Host "Installing to $instDir..."
   cmd /c start /wait $exePath /silent /verysilent /sp- /suppressmsgboxes /DIR=$instDir
   Write-Host "Installed" -ForegroundColor Green
} else {
   echo "OpenSSL-Win32 already exists: not downloading"
}


if (!(Test-Path("C:\OpenSSL-Win64"))) {
   instDir = "C:\OpenSSL-Win64"
   $exeFull = "Win64$OpenSSLExe"
   $exePath = "$($env:USERPROFILE)\$exeFull"

   Write-Host "Downloading and installing OpenSSL v1.1 64-bit ..." -ForegroundColor Cyan
   (New-Object Net.WebClient).DownloadFile('https://slproweb.com/download/$exeFull', $exePath)

   Write-Host "Installing to $instDir..."
   cmd /c start /wait $exePath /silent /verysilent /sp- /suppressmsgboxes /DIR=$instDir
   Write-Host "Installed" -ForegroundColor Green
} else {
   echo "OpenSSL-Win64 already exists: not downloading"
}

setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"
path "C:\Program Files (x86)\MSBuild\16.0\Bin;C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin";%path%
cmake -G "Visual Studio 16 2019" .
msbuild cmetrics.sln /property:Configuration=Debug -maxcpucount:2
endlocal
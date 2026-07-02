@echo off

SET TOOLCHAIN=v140

FOR %%C IN (Debug,Release) DO (
  FOR %%P IN (Win32,x64) DO (
     @echo Building %%C %%P
     msbuild librdkafka.sln /p:Configuration=%%C /p:Platform=%%P /target:Clean
     msbuild librdkafka.sln /p:Configuration=%%C /p:Platform=%%P || goto :error


  )
)

exit /b 0

:error
echo "Build failed"
exit /b 1

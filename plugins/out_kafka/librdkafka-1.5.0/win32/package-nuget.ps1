<#
.SYNOPSIS

   Create NuGet package using CoApp


.DESCRIPTION

   A full build must be completed, to populate output directories, before

   running this script.

   Use build.bat to build


   Requires CoApp
#>



Write-NuGetPackage librdkafka.autopkg

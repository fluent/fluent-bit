set pkgversion=0.9.3-pre-wip1
nuget push librdkafka.%pkgversion%.nupkg -Source https://www.nuget.org/api/v2/package
nuget push librdkafka.redist.%pkgversion%.nupkg -Source https://www.nuget.org/api/v2/package
nuget push librdkafka.symbols.%pkgversion%.nupkg -Source https://www.nuget.org/api/v2/package

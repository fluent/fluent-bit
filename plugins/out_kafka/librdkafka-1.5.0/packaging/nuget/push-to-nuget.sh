#!/bin/bash
#
# Upload NuGet package to NuGet.org using provided NuGet API key
#

set -e

key=$1
pkg=$2

if [[ -z $pkg ]]; then
    echo "Usage: $0 <nuget.org-api-key> <nuget-package>"
    exit 1
fi

set -u

docker run -t -v $PWD/$pkg:/$pkg microsoft/dotnet:sdk \
       dotnet nuget push /$pkg -n -s https://api.nuget.org/v3/index.json \
       -k $key --source https://api.nuget.org/v3/index.json


# NuGet package assembly

This set of scripts collect CI artifacts from S3 and assembles
them into a NuGet package structure staging directory.
The NuGet tool is then run (from within docker) on this staging directory
to create a proper NuGet package (with all the metadata).

The finalized nuget package maybe uploaded manually to NuGet.org

## Requirements

 * Requires Python 2.x (due to Python 3 compat issues with rpmfile)
 * Requires Docker
 * Requires private S3 access keys for the librdkafka-ci-packages bucket.



## Usage

1. Trigger CI builds by creating and pushing a new release (candidate) tag
   in the librdkafka repo. Make sure the tag is created on the correct branch.

    $ git tag v0.11.0
    $ git push origin v0.11.0

2. Wait for CI builds to finish, monitor the builds here:

 * https://travis-ci.org/edenhill/librdkafka
 * https://ci.appveyor.com/project/edenhill/librdkafka

3. On a Linux host, run the release.py script to assemble the NuGet package

    $ cd packaging/nuget
    # Specify the tag
    $ ./release.py v0.11.0
    # Optionally, if the tag was moved and an exact sha is also required:
    # $ ./release.py --sha <the-full-git-sha> v0.11.0

4. If all artifacts were available the NuGet package will be built
   and reside in the current directory as librdkafka.redist.<v-less-tag>.nupkg

5. Test the package manually

6. Upload the package to NuGet

 * https://www.nuget.org/packages/manage/upload

7. If you trust this process you can have release.py upload the package
   automatically to NuGet after building it:

    $ ./release.py --retries 100 --upload your-nuget-api.key v0.11.0



## Other uses

### Create static library bundles

To create a bundle (tarball) of librdkafka self-contained static library
builds, use the following command:

    $ ./release.py --class StaticPackage v1.1.0

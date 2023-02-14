# librdkafka release process

This guide outlines the steps needed to release a new version of librdkafka
and publish packages to channels (NuGet, Homebrew, etc,..).

Releases are done in two phases:
 * release-candidate(s) - RC1 will be the first release candidate, and any
   changes to the repository will require a new RC.
 * final release - the final release is based directly on the last RC tag
   followed by a single version-bump commit (see below).

Release tag and version format:
 * tagged release builds to verify CI release builders: vA.B.C-PREn
 * release-candidate: vA.B.C-RCn
 * final release: vA.B.C


## Update protocol requests and error codes

Check out the latest version of Apache Kafka (not trunk, needs to be a released
version since protocol may change on trunk).

### Protocol request types

Generate protocol request type codes with:

    $ src/generate_proto.sh ~/src/your-kafka-dir

Cut'n'paste the new defines and strings to `rdkafka_protocol.h` and
`rdkafka_proto.h`.

### Error codes

Error codes must currently be parsed manually, open
`clients/src/main/java/org/apache/kafka/common/protocol/Errors.java`
in the Kafka source directory and update the `rd_kafka_resp_err_t` and
`RdKafka::ErrorCode` enums in `rdkafka.h` and `rdkafkacpp.h`
respectively.
Add the error strings to `rdkafka.c`.
The Kafka error strings are sometimes a bit too verbose for our taste,
so feel free to rewrite them (usually removing a couple of 'the's).
Error strings must not contain a trailing period.

**NOTE**: Only add **new** error codes, do not alter existing ones since that
          will be a breaking API change.


## Run regression tests

**Build tests:**

    $ cd tests
    $ make -j build

**Run the full regression test suite:** (requires Linux and the trivup python package)

    $ make full


If all tests pass, carry on, otherwise identify and fix bug and start over.



## Write release notes / changelog

All relevant PRs should also include an update to [CHANGELOG.md](../CHANGELOG.md)
that in a user-centric fashion outlines what changed.
It might not be practical for all contributors to write meaningful changelog
entries, so it is okay to add them separately later after the PR has been
merged (make sure to credit community contributors for their work).

The changelog should include:
 * What type of release (maintenance or feature release)
 * A short intro to the release, describing the type of release: maintenance
   or feature release, as well as fix or feature high-lights.
 * A section of **New features**, if any.
 * A section of **Upgrade considerations**, if any, to outline important changes
   that require user attention.
 * A section of **Enhancements**, if any.
 * A section of **Fixes**, if any, preferably with Consumer, Producer, and
   Generic sub-sections.


## Pre-release code tasks

**Switch to the release branch which is of the format `A.B.C.x` or `A.B.x`.**

    $ git checkout -b 0.11.1.x


**Update in-code versions.**

The last octet in the version hex number is the pre-build/release-candidate
number, where 0xAABBCCff is the final release for version 0xAABBCC.
Release candidates start at 200, thus 0xAABBCCc9 is RC1, 0xAABBCCca is RC2, etc.

Change the `RD_KAFKA_VERSION` defines in both `src/rdkafka.h` and
`src-cpp/rdkafkacpp.h` to the version to build, such as 0x000b01c9
for v0.11.1-RC1, or 0x000b01ff for the final v0.11.1 release.
Update the librdkafka version in `vcpkg.json`.

   # Update defines
   $ $EDITOR src/rdkafka.h src-cpp/rdkafkacpp.h vcpkg.json

   # Reconfigure and build
   $ ./configure
   $ make

   # Check git diff for correctness
   $ git diff

   # Commit
   $ git commit -m "Version v0.11.1-RC1" src/rdkafka.h src-cpp/rdkafkacpp.h


**Create tag.**

    $ git tag v0.11.1-RC1 # for an RC
    # or for the final release:
    $ git tag v0.11.1     # for the final release


**Push branch and commit to github**

    # Dry-run first to make sure things look correct
    $ git push --dry-run origin 0.11.1.x

    # Live
    $ git push origin 0.11.1.x
**Push tags and commit to github**

    # Dry-run first to make sure things look correct.
    $ git push --dry-run --tags origin v0.11.1-RC1

    # Live
    $ git push --tags origin v0.11.1-RC1


## Creating packages

As soon as a tag is pushed the CI systems (Travis and AppVeyor) will
start their builds and eventually upload the packaging artifacts to S3.
Wait until this process is finished by monitoring the two CIs:

 * https://travis-ci.org/edenhill/librdkafka
 * https://ci.appveyor.com/project/edenhill/librdkafka


### Create NuGet package

On a Linux host with docker installed, this will also require S3 credentials
to be set up.

    $ cd packaging/nuget
    $ python3 -m pip install -r requirements.txt  # if necessary
    $ ./release.py v0.11.1-RC1

Test the generated librdkafka.redist.0.11.1-RC1.nupkg and
then upload it to NuGet manually:

 * https://www.nuget.org/packages/manage/upload


### Create static bundle (for Go)

    $ cd packaging/nuget
    $ ./release.py --class StaticPackage v0.11.1-RC1

Follow the Go client release instructions for updating its bundled librdkafka
version based on the tar ball created here.


## Publish release on github

Create a release on github by going to https://github.com/edenhill/librdkafka/releases
and Draft a new release.
Name the release the same as the final release tag (e.g., `v1.9.0`) and set
the tag to the same.
Paste the CHANGELOG.md section for this release into the release description,
look at the preview and fix any formatting issues.

Run the following command to get checksums of the github release assets:

    $ packaging/tools/gh-release-checksums.py <the-tag>

It will take some time for the script to download the files, when done
paste the output to the end of the release page.

Make sure the release page looks okay, is still correct (check for new commits),
and has the correct tag, then click Publish release.



### Homebrew recipe update

**Note**: This is typically not needed since homebrew seems to pick up new
    release versions quickly enough.

The brew-update-pr.sh script automatically pushes a PR to homebrew-core
with a patch to update the librdkafka version of the formula.
This should only be done for final releases and not release candidates.

On a MacOSX host with homebrew installed:

    $ cd package/homebrew
    # Dry-run first to see that things are okay.
    $ ./brew-update-pr.sh v0.11.1
    # If everything looks good, do the live push:
    $ ./brew-update-pr.sh --upload v0.11.1


### Deb and RPM packaging

Debian and RPM packages are generated by Confluent packaging in a separate
process and the resulting packages are made available on Confluent's
APT and YUM repositories.

That process is outside the scope of this document.

See the Confluent docs for instructions how to access these packages:
https://docs.confluent.io/current/installation.html

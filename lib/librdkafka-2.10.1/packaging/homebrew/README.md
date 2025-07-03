# Update the Homebrew librdkafka package version

The `./brew-update-pr.sh` script in this directory updates the
brew formula for librdkafka and pushes a PR to the homebrew-core repository.

You should run it in two steps, first an implicit dry-run mode
to check that things seem correct, and if that checks out a
live upload mode which actually pushes the PR.

    # Do a dry-run first, v0.11.0 is the librdkafka tag:
    $ ./brew-update-pr.sh v0.11.0

    # If everything looks okay, run the live upload mode:
    $ ./brew-update-pr.sh --upload v0.11.0


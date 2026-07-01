# shUnit2 2.1.7 Release Notes

https://github.com/kward/shunit2

This release contains bug fixes and enhancements. It is the first release since moving to GitHub. Users can now clone the latest version at any time.

See the `CHANGES-2.1.md` file for a full list of changes.


## New Features

Colorized output, based on popular demand. shUnit2 output is now colorized based on the result of the asserts.


## Changes and Enhancements

With the move to GitHub, the shUnit2 unit tests are run on every commit using the [Travis CI][TravisCI] continuous integration framework. Additionally, all code is run through [ShellCheck](http:/www.shellcheck.net/) on every commit.

[TravisCI]: https://travis-ci.org/kward/shunit2

Shell commands in shUnit2 are prefixed with '\' so that they can be stubbed in tests.


## Bug Fixes

shUnit2 no longer exits with an 'OK' result if there were syntax errors due to incorrect usage of the assert commands.


## Deprecated Features

None.


## Known Bugs and Issues

Zsh requires the `shwordsplit` option to be set. See the documentation for examples of how to do this.

Line numbers in assert messages do not work properly with BASH 2.x.

The Bourne shell of Solaris, BASH 2.x, and Zsh 3.0.x do not properly catch the
SIGTERM signal. As such, shell interpreter failures due to such things as
unbound variables cannot be caught. (See `shunit_test_misc.sh`)


## Tested Platforms

Continuous integration testing is provided by
[Travis CI](https://travis-ci.org/).

https://travis-ci.org/github/kward/shunit2

Tested OSes:

- Linux
- macOS

Tested shells:

- /bin/sh
- ash
- bash
- dash
- ksh
- pdksh
- zsh


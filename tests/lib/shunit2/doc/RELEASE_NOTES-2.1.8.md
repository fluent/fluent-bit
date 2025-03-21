# shUnit2 2.1.8 Release Notes

https://github.com/kward/shunit2

This release contains bug fixes and enhancements. See the `CHANGES-2.1.md` file
for a full list of changes.

## New features

Users can now define a custom prefix for test function names. The prefix can be
configured by defining a `SHUNIT_TEST_PREFIX` variable.

## Bug fixes

Syntax errors in functions are now treated as test failures.

Test now fail when `setup()` or `tearDown()` fail.

## Deprecated features

None.

## Known bugs and issues

Zsh requires the `shwordsplit` option to be set. See the documentation for examples of how to do this.

Line numbers in assert messages do not work properly with BASH 2.x.

The Bourne shell of Solaris, BASH 2.x, and Zsh 3.0.x do not properly catch the
SIGTERM signal. As such, shell interpreter failures due to such things as
unbound variables cannot be caught. (See `shunit_test_misc.sh`)

shUnit2 does not work when the `-e` shell option is set (typically done with
`set -e`).

## Tested platforms

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

# shUnit2

shUnit2 is a [xUnit](http://en.wikipedia.org/wiki/XUnit) unit test framework for
Bourne based shell scripts, and it is designed to work in a similar manner to
[JUnit](http://www.junit.org), [PyUnit](http://pyunit.sourceforge.net), etc.. If
you have ever had the desire to write a unit test for a shell script, shUnit2
can do the job.

[![Travis CI](https://img.shields.io/travis/kward/shunit2.svg)](https://travis-ci.org/kward/shunit2)

## Table of Contents

* [Introduction](#introduction)
  * [Credits / Contributors](#credits-contributors)
  * [Feedback](#feedback)
* [Quickstart](#quickstart)
* [Function Reference](#function-reference)
  * [General Info](#general-info)
  * [Asserts](#asserts)
  * [Failures](#failures)
  * [Setup/Teardown](#setup-teardown)
  * [Skipping](#skipping)
  * [Suites](#suites)
* [Advanced Usage](#advanced-usage)
  * [Some constants you can use](#some-constants-you-can-use)
  * [Error Handling](#error-handling)
  * [Including Line Numbers in Asserts (Macros)](#including-line-numbers-in-asserts-macros)
  * [Test Skipping](#test-skipping)
  * [Running specific tests from the command line](#cmd-line-args)
* [Appendix](#appendix)
  * [Getting help](#getting-help)
  * [Zsh](#zsh)

---

## <a name="introduction"></a> Introduction

shUnit2 was originally developed to provide a consistent testing solution for
[log4sh][log4sh], a shell based logging framework similar to
[log4j](http://logging.apache.org). During the development of that product, a
repeated problem of having things work just fine under one shell (`/bin/bash` on
Linux to be specific), and then not working under another shell (`/bin/sh` on
Solaris) kept coming up. Although several simple tests were run, they were not
adequate and did not catch some corner cases. The decision was finally made to
write a proper unit test framework after multiple brown-bag releases were made.
_Research was done to look for an existing product that met the testing
requirements, but no adequate product was found._

### Tested software

**Tested Operating Systems** (varies over time)

OS                                  | Support   | Verified
----------------------------------- | --------- | --------
Ubuntu Linux (14.04.05 LTS)         | Travis CI | continuous
macOS High Sierra (10.13.3)         | Travis CI | continuous
FreeBSD                             | user      | unknown
Solaris 8, 9, 10 (inc. OpenSolaris) | user      | unknown
Cygwin                              | user      | unknown

**Tested Shells**

* Bourne Shell (__sh__)
* BASH - GNU Bourne Again SHell (__bash__)
* DASH (__dash__)
* Korn Shell (__ksh__)
* pdksh - Public Domain Korn Shell (__pdksh__)
* zsh - Zsh (__zsh__) (since 2.1.2) _please see the Zsh shell errata for more information_

See the appropriate Release Notes for this release
(`doc/RELEASE_NOTES-X.X.X.txt`) for the list of actual versions tested.

### <a name="credits-contributors"></a> Credits / Contributors

A list of contributors to shUnit2 can be found in `doc/contributors.md`. Many
thanks go out to all those who have contributed to make this a better tool.

shUnit2 is the original product of many hours of work by Kate Ward, the primary
author of the code. For related software, check out https://github.com/kward.

### <a name="feedback"></a> Feedback

Feedback is most certainly welcome for this document. Send your questions,
comments, and criticisms via the
[shunit2-users](https://groups.google.com/a/forestent.com/forum/#!forum/shunit2-users/new)
forum (created 2018-12-09), or file an issue via
https://github.com/kward/shunit2/issues.

---

## <a name="quickstart"></a> Quickstart

This section will give a very quick start to running unit tests with shUnit2.
More information is located in later sections.

Here is a quick sample script to show how easy it is to write a unit test in
shell. _Note: the script as it stands expects that you are running it from the
"examples" directory._

```sh
#! /bin/sh
# file: examples/equality_test.sh

testEquality() {
  assertEquals 1 1
}

# Load shUnit2.
. ./shunit2
```

Running the unit test should give results similar to the following.

```console
$ cd examples
$ ./equality_test.sh
testEquality

Ran 1 test.

OK
```

W00t! You've just run your first successful unit test. So, what just happened?
Quite a bit really, and it all happened simply by sourcing the `shunit2`
library. The basic functionality for the script above goes like this:

* When shUnit2 is sourced, it will walk through any functions defined whose name
  starts with the string `test`, and add those to an internal list of tests to
  execute. Once a list of test functions to be run has been determined, shunit2
  will go to work.
* Before any tests are executed, shUnit2 again looks for a function, this time
  one named `oneTimeSetUp()`. If it exists, it will be run. This function is
  normally used to setup the environment for all tests to be run. Things like
  creating directories for output or setting environment variables are good to
  place here. Just so you know, you can also declare a corresponding function
  named `oneTimeTearDown()` function that does the same thing, but once all the
  tests have been completed. It is good for removing temporary directories, etc.
* shUnit2 is now ready to run tests. Before doing so though, it again looks for
  another function that might be declared, one named `setUp()`. If the function
  exists, it will be run before each test. It is good for resetting the
  environment so that each test starts with a clean slate. **At this stage, the
  first test is finally run.** The success of the test is recorded for a report
  that will be generated later. After the test is run, shUnit2 looks for a final
  function that might be declared, one named `tearDown()`. If it exists, it will
  be run after each test. It is a good place for cleaning up after each test,
  maybe doing things like removing files that were created, or removing
  directories. This set of steps, `setUp() > test() > tearDown()`, is repeated
  for all of the available tests.
* Once all the work is done, shUnit2 will generate the nice report you saw
  above. A summary of all the successes and failures will be given so that you
  know how well your code is doing.

We should now try adding a test that fails. Change your unit test to look like
this.

```sh
#! /bin/sh
# file: examples/party_test.sh

testEquality() {
  assertEquals 1 1
}

testPartyLikeItIs1999() {
  year=`date '+%Y'`
  assertEquals "It's not 1999 :-(" '1999' "${year}"
}

# Load shUnit2.
. ./shunit2
```

So, what did you get? I guess it told you that this isn't 1999. Bummer, eh?
Hopefully, you noticed a couple of things that were different about the second
test. First, we added an optional message that the user will see if the assert
fails. Second, we did comparisons of strings instead of integers as in the first
test. It doesn't matter whether you are testing for equality of strings or
integers. Both work equally well with shUnit2.

Hopefully, this is enough to get you started with unit testing. If you want a
ton more examples, take a look at the tests provided with [log4sh][log4sh] or
[shFlags][shflags]. Both provide excellent examples of more advanced usage.
shUnit2 was after all written to meet the unit testing need that
[log4sh][log4sh] had.

---

## <a name="function-reference"></a> Function Reference

### <a name="general-info"></a> General Info

Any string values passed should be properly quoted -- they should must be
surrounded by single-quote (`'`) or double-quote (`"`) characters -- so that the
shell will properly parse them.

### <a name="asserts"></a> Asserts

`assertEquals [message] expected actual`

Asserts that _expected_ and _actual_ are equal to one another. The _expected_
and _actual_ values can be either strings or integer values as both will be
treated as strings. The _message_ is optional, and must be quoted.

`assertNotEquals [message] unexpected actual`

Asserts that _unexpected_ and _actual_ are not equal to one another. The
_unexpected_ and _actual_ values can be either strings or integer values as both
will be treaded as strings. The _message_ is optional, and must be quoted.

`assertSame [message] expected actual`

This function is functionally equivalent to `assertEquals`.

`assertNotSame [message] unexpected actual`

This function is functionally equivalent to `assertNotEquals`.

`assertContains [message] container content`

Asserts that _container_ contains _content_. The _container_ and _content_
values can be either strings or integer values as both will be treated as
strings. The _message_ is optional, and must be quoted.

`assertNotContains [message] container content`

Asserts that _container_ does not contain _content_. The _container_ and
_content_ values can be either strings or integer values as both will be treaded
as strings. The _message_ is optional, and must be quoted.

`assertNull [message] value`

Asserts that _value_ is _null_, or in shell terms, a zero-length string. The
_value_ must be a string as an integer value does not translate into a zero-
length string. The _message_ is optional, and must be quoted.

`assertNotNull [message] value`

Asserts that _value_ is _not null_, or in shell terms, a non-empty string. The
_value_ may be a string or an integer as the later will be parsed as a non-empty
string value. The _message_ is optional, and must be quoted.

`assertTrue [message] condition`

Asserts that a given shell test _condition_ is _true_. The condition can be as
simple as a shell _true_ value (the value `0` -- equivalent to
`${SHUNIT_TRUE}`), or a more sophisticated shell conditional expression. The
_message_ is optional, and must be quoted.

A sophisticated shell conditional expression is equivalent to what the __if__ or
__while__ shell built-ins would use (more specifically, what the __test__
command would use). Testing for example whether some value is greater than
another value can be done this way.

`assertTrue "[ 34 -gt 23 ]"`

Testing for the ability to read a file can also be done. This particular test
will fail.

`assertTrue 'test failed' "[ -r /some/non-existant/file' ]"`

As the expressions are standard shell __test__ expressions, it is possible to
string multiple expressions together with `-a` and `-o` in the standard fashion.
This test will succeed as the entire expression evaluates to _true_.

`assertTrue 'test failed' '[ 1 -eq 1 -a 2 -eq 2 ]'`

<i>One word of warning: be very careful with your quoting as shell is not the
most forgiving of bad quoting, and things will fail in strange ways.</i>

`assertFalse [message] condition`

Asserts that a given shell test _condition_ is _false_. The condition can be as
simple as a shell _false_ value (the value `1` -- equivalent to
`${SHUNIT_FALSE}`), or a more sophisticated shell conditional expression. The
_message_ is optional, and must be quoted.

_For examples of more sophisticated expressions, see `assertTrue`._

### <a name="failures"></a> Failures

Just to clarify, failures __do not__ test the various arguments against one
another. Failures simply fail, optionally with a message, and that is all they
do. If you need to test arguments against one another, use asserts.

If all failures do is fail, why might one use them? There are times when you may
have some very complicated logic that you need to test, and the simple asserts
provided are simply not adequate. You can do your own validation of the code,
use an `assertTrue ${SHUNIT_TRUE}` if your own tests succeeded, and use a
failure to record a failure.

`fail [message]`

Fails the test immediately. The _message_ is optional, and must be quoted.

`failNotEquals [message] unexpected actual`

Fails the test immediately, reporting that the _unexpected_ and _actual_ values
are not equal to one another. The _message_ is optional, and must be quoted.

_Note: no actual comparison of unexpected and actual is done._

`failSame [message] expected actual`

Fails the test immediately, reporting that the _expected_ and _actual_ values
are the same. The _message_ is optional, and must be quoted.

_Note: no actual comparison of expected and actual is done._

`failNotSame [message] expected actual`

Fails the test immediately, reporting that the _expected_ and _actual_ values
are not the same. The _message_ is optional, and must be quoted.

_Note: no actual comparison of expected and actual is done._

`failFound [message] content`

Fails the test immediately, reporting that the _content_ was found. The
_message_ is optional, and must be quoted.

_Note: no actual search of content is done._

`failNotFound [message] content`

Fails the test immediately, reporting that the _content_ was not found. The
_message_ is optional, and must be quoted.

_Note: no actual search of content is done._

### <a name="setup-teardown"></a> Setup/Teardown

`oneTimeSetUp`

This function can be be optionally overridden by the user in their test suite.

If this function exists, it will be called once before any tests are run. It is
useful to prepare a common environment for all tests.

`oneTimeTearDown`

This function can be be optionally overridden by the user in their test suite.

If this function exists, it will be called once after all tests are completed.
It is useful to clean up the environment after all tests.

`setUp`

This function can be be optionally overridden by the user in their test suite.

If this function exists, it will be called before each test is run. It is useful
to reset the environment before each test.

`tearDown`

This function can be be optionally overridden by the user in their test suite.

If this function exists, it will be called after each test completes. It is
useful to clean up the environment after each test.

### <a name="skipping"></a> Skipping

`startSkipping`

This function forces the remaining _assert_ and _fail_ functions to be
"skipped", i.e. they will have no effect. Each function skipped will be recorded
so that the total of asserts and fails will not be altered.

`endSkipping`

This function returns calls to the _assert_ and _fail_ functions to their
default behavior, i.e. they will be called.

`isSkipping`

This function returns the current state of skipping. It can be compared against
`${SHUNIT_TRUE}` or `${SHUNIT_FALSE}` if desired.

### <a name="suites"></a> Suites

The default behavior of shUnit2 is that all tests will be found dynamically. If
you have a specific set of tests you want to run, or you don't want to use the
standard naming scheme of prefixing your tests with `test`, these functions are
for you. Most users will never use them though.

`suite`

This function can be optionally overridden by the user in their test suite.

If this function exists, it will be called when `shunit2` is sourced. If it does
not exist, shUnit2 will search the parent script for all functions beginning
with the word `test`, and they will be added dynamically to the test suite.

`suite_addTest name`

This function adds a function named _name_ to the list of tests scheduled for
execution as part of this test suite. This function should only be called from
within the `suite()` function.

---

## <a name="advanced-usage"></a> Advanced Usage

### <a name="some-constants-you-can-use"></a> Some constants you can use

There are several constants provided by shUnit2 as variables that might be of
use to you.

*Predefined*

| Constant        | Value |
| --------------- | ----- |
| SHUNIT\_TRUE    | Standard shell `true` value (the integer value 0). |
| SHUNIT\_FALSE   | Standard shell `false` value (the integer value 1). |
| SHUNIT\_ERROR   | The integer value 2. |
| SHUNIT\_TMPDIR  | Path to temporary directory that will be automatically cleaned up upon exit of shUnit2. |
| SHUNIT\_VERSION | The version of shUnit2 you are running. |

*User defined*

| Constant          | Value |
| ----------------- | ----- |
| SHUNIT\_CMD\_EXPR | Override which `expr` command is used. By default `expr` is used, except on BSD systems where `gexpr` is used. |
| SHUNIT\_COLOR     | Enable colorized output. Options are 'auto', 'always', or 'none', with 'auto' being the default. |
| SHUNIT\_PARENT    | The filename of the shell script containing the tests. This is needed specifically for Zsh support. |
| SHUNIT\_TEST\_PREFIX | Define this variable to add a prefix in front of each test name that is output in the test report. |

### <a name="error-handling"></a> Error handling

The constants values `SHUNIT_TRUE`, `SHUNIT_FALSE`, and `SHUNIT_ERROR` are
returned from nearly every function to indicate the success or failure of the
function. Additionally the variable `flags_error` is filled with a detailed
error message if any function returns with a `SHUNIT_ERROR` value.

### <a name="including-line-numbers-in-asserts-macros"></a> Including Line Numbers in Asserts (Macros)

If you include lots of assert statements in an individual test function, it can
become difficult to determine exactly which assert was thrown unless your
messages are unique. To help somewhat, line numbers can be included in the
assert messages. To enable this, a special shell "macro" must be used rather
than the standard assert calls. _Shell doesn't actually have macros; the name is
used here as the operation is similar to a standard macro._

For example, to include line numbers for a `assertEquals()` function call,
replace the `assertEquals()` with `${_ASSERT_EQUALS_}`.

_**Example** -- Asserts with and without line numbers_

```sh
#! /bin/sh
# file: examples/lineno_test.sh

testLineNo() {
  # This assert will have line numbers included (e.g. "ASSERT:[123] ...").
  echo "ae: ${_ASSERT_EQUALS_}"
  ${_ASSERT_EQUALS_} 'not equal' 1 2

  # This assert will not have line numbers included (e.g. "ASSERT: ...").
  assertEquals 'not equal' 1 2
}

# Load shUnit2.
. ./shunit2
```

Notes:

1. Due to how shell parses command-line arguments, all strings used with macros
   should be quoted twice. Namely, single-quotes must be converted to single-
   double-quotes, and vice-versa. If the string being passed is absolutely for
   sure not empty, the extra quoting is not necessary.<br/>
   <br/>
   Normal `assertEquals` call.<br/>
   `assertEquals 'some message' 'x' ''`<br/>
   <br/>
   Macro `_ASSERT_EQUALS_` call. Note the extra quoting around the _message_ and
   the _null_ value.<br/>
   `_ASSERT_EQUALS_ '"some message"' 'x' '""'`

1. Line numbers are not supported in all shells. If a shell does not support
   them, no errors will be thrown. Supported shells include: __bash__ (>=3.0),
   __ksh__, __pdksh__, and __zsh__.

### <a name="test-skipping"></a> Test Skipping

There are times where the test code you have written is just not applicable to
the system you are running on. This section describes how to skip these tests
but maintain the total test count.

Probably the easiest example would be shell code that is meant to run under the
__bash__ shell, but the unit test is running under the Bourne shell. There are
things that just won't work. The following test code demonstrates two sample
functions, one that will be run under any shell, and the another that will run
only under the __bash__ shell.

_**Example** -- math include_
```sh
# file: examples/math.inc.

add_generic() {
  num_a=$1
  num_b=$2

  expr $1 + $2
}

add_bash() {
  num_a=$1
  num_b=$2

  echo $(($1 + $2))
}
```

And here is a corresponding unit test that correctly skips the `add_bash()` function when the unit test is not running under the __bash__ shell.

_**Example** -- math unit test_
```sh
#! /bin/sh
# file: examples/math_test.sh

testAdding() {
  result=`add_generic 1 2`
  assertEquals \
      "the result of '${result}' was wrong" \
      3 "${result}"

  # Disable non-generic tests.
  [ -z "${BASH_VERSION:-}" ] && startSkipping

  result=`add_bash 1 2`
  assertEquals \
      "the result of '${result}' was wrong" \
      3 "${result}"
}

oneTimeSetUp() {
  # Load include to test.
  . ./math.inc
}

# Load and run shUnit2.
. ./shunit2
```

Running the above test under the __bash__ shell will result in the following
output.

```console
$ /bin/bash math_test.sh
testAdding

Ran 1 test.

OK
```

But, running the test under any other Unix shell will result in the following
output.

```console
$ /bin/ksh math_test.sh
testAdding

Ran 1 test.

OK (skipped=1)
```

As you can see, the total number of tests has not changed, but the report
indicates that some tests were skipped.

Skipping can be controlled with the following functions: `startSkipping()`,
`endSkipping()`, and `isSkipping()`. Once skipping is enabled, it will remain
enabled until the end of the current test function call, after which skipping is
disabled.

### <a name="cmd-line-args"></a> Running specific tests from the command line.

When running a test script, you may override the default set of tests, or the suite-specified set of tests, by providing additional arguments on the command line.  Each additional argument after the `--` marker is assumed to be the name of a test function to be run in the order specified.  e.g.

```console
test-script.sh -- testOne testTwo otherFunction
```

or

```console
shunit2 test-script.sh testOne testTwo otherFunction
```

In either case, three functions will be run as tests, `testOne`, `testTwo`, and `otherFunction`.  Note that the function `otherFunction` would not normally be run by `shunit2` as part of the implicit collection of tests as it's function name does not match the test function name pattern `test*`.

If a specified test function does not exist, `shunit2` will still attempt to run that function and thereby cause a failure which `shunit2` will catch and mark as a failed test.  All other tests will run normally.

The specification of tests does not affect how `shunit2` looks for and executes the setup and tear down functions, which will still run as expected.

---

## <a name="appendix"></a> Appendix

### <a name="getting-help"></a> Getting Help

For help, please send requests to either the shunit2-users@forestent.com mailing
list (archives available on the web at
https://groups.google.com/a/forestent.com/forum/#!forum/shunit2-users) or
directly to Kate Ward <kate dot ward at forestent dot com>.

### <a name="zsh"></a> Zsh

For compatibility with Zsh, there is one requirement that must be met -- the
`shwordsplit` option must be set. There are three ways to accomplish this.

1. In the unit-test script, add the following shell code snippet before sourcing
   the `shunit2` library.

   ```sh
   setopt shwordsplit
   ```

2. When invoking __zsh__ from either the command-line or as a script with `#!`,
   add the `-y` parameter.

    ```sh
    #! /bin/zsh -y
    ```

3. When invoking __zsh__ from the command-line, add `-o shwordsplit --` as
   parameters before the script name.

   ```console
   $ zsh -o shwordsplit -- some_script
   ```

[log4sh]: https://github.com/kward/log4sh
[shflags]: https://github.com/kward/shflags

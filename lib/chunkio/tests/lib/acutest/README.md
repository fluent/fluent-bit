[![Build status (travis-ci.com)](https://img.shields.io/travis/mity/acutest/master.svg?label=linux%20build)](https://travis-ci.org/mity/acutest)
[![Build status (appveyor.com)](https://img.shields.io/appveyor/ci/mity/acutest/master.svg?label=windows%20build)](https://ci.appveyor.com/project/mity/acutest/branch/master)


# Acutest Readme

Home: http://github.com/mity/acutest


## What Is Acutest

"Acutest" means "Another C Unit Testing" and it is intended to do exactly that,
while being as simple as possible to use it, not to stand in the developer's
way and minimize any external dependencies.

To achieve that, the complete implementation resides in a single C header file,
and its core depends only on few standard C library functions.

Acutest supports C as well as C++, and it can deal with unit tests which throw
C++ exceptions.


## Overview

**Main features:**
* Unit tests in C or C++ are supported.
* No need to install/setup/configure testing framework. Acutest is just single
  C/C++ header, `"acutest.h"`.
* The header provides program entry point (function `main()`).
* Minimal dependencies: Core features only depend on few standard C headers,
  optional features may use more if available on the particular system.
* Trivial interface for writing unit tests: Few preprocessor macros described
  further below.

**Windows specific features:**
* By default, every unit test is executed as a child process.
* By default, if the output is directed to a terminal, the output is colorized.
* Acutest installs a SEH filter to print out uncaught SEH exceptions.

**Unix specific features:**
* By default, every unit test is executed as a child process.
* By default, if the output is directed to a terminal, the output is colorized.

**C++ specific features:**
* Acutest catches C++ exceptions thrown from unit test functions. Such unit
  tests are considered to fail.
* If the exception is derived from `std::exception`, `what()` is written out
  in the error message.

Any C/C++ module implementing one or more unit tests and including `"acutest.h"`,
can be built as a standalone program. We call the resulted binary as a "test
suite" for purposes of this document. The suite is then executed to run the
tests, as specified with its command line options.

By default, all unit tests in the program are run and (on Windows and Unix)
every unit test is executed in a context of its own subprocess. Both can be
overridden on the command line.

We say any unit test succeeds if all conditions (preprocessor macros `TEST_CHECK`
or `TEST_CHECK_`) called throughout its execution pass, the test does not throw
an exception (C++ only), and (on Windows/Unix) the unit test subprocess is not
interrupted/terminated (e.g. by a signal on Unix or SEH on Windows).

Exit code of the test suite is 0 if all unit tests pass, 1 if any of them fails,
or other number if an internal error occurs.


## Writing Unit Tests

To use Acutest, simply include the header file `"acutest.h"` on the beginning
of the C/C++ source file implementing one or more unit tests. Note the header
provides implementation of the `main()` function.

```C
#include "acutest.h"
```

Every test is supposed to be implemented as a function with the following
prototype:

```C
void test_example(void);
```

The tests can use preprocessor macro `TEST_CHECK` or `TEST_CHECK_` to validate the
test conditions. They can be used multiple times, and if any of those conditions
fails, the particular test is considered to fail.

(The macro `TEST_CHECK_` can be used only if your C preprocessor supports variadic
macros: it takes printf-like extra arguments to provide a custom error message
if the condition fails.)

For example:

```C
void test_example(void)
{
    void* mem;
    int a, b;

    mem = malloc(10);
    TEST_CHECK(mem != NULL);

    mem = realloc(mem, 20);
    TEST_CHECK(mem != NULL);

    a = 1;
    b = 2;
    TEST_CHECK_(a + b == 3, "Expected %d, got %d", 3, a + b);
}
```

Note that the tests should be independent on each other. Whenever the test
suite is invoked, the user may run any number of tests in the suite, in any
order. Furthermore by default, on platforms where supported, each unit test
is executed as a standalone (sub)process.

Finally, the test suite source file has to list the unit tests, using the
macro `TEST_LIST`. The list specifies name of each test (it has to be unique)
and pointer to a function implementing the test. I recommend names which are
easy to use on command line, i.e. especially avoid space and other special
characters in them. Also avoid using dash as a first character, as it would
be then interpreted as a command line option, not a test name.

```C
TEST_LIST = {
   { "example", test_example },
   ...
   { 0 }
};
```

Note the test list has to be ended with zeroed record.

Finally you just compile the C/C++ test suite source file as a simple program.
For example, assuming `cc` is your C compiler:

```sh
$ cc test_example.c -o test_example
```

More comprehensive description of API can be found in comments in the header
`"acutest.h"`.


## Running Unit Tests

When the source file implementing the tests is compiled, the resulted testing
binary can be used to run the tests.

By default (without any command line options), it runs all implemented unit
tests. It can also run only subset of the unit tests as specified on the
command line:

```sh
$ ./test_example                # Runs all tests in the suite
$ ./test_example test1 test2    # Runs only tests specified
$ ./test_example --skip test3   # Runs all tests but those specified
```

Acutest implements several levels of unit test selection. Note the first rule
which successfully finds non-empty set of unit tests applies:

1. Exact match: Applies when the command line argument matches exactly name
   of any unit test.

2. Word match: Applies when the command line argument matches whole word
   of any unit test. (Space ` `, tabulator `\t`, dash `-` and underscore `_`
   are understood as word delimiters in test names.)

3. Relaxed match: Applies when the command line argument matches any substring
   in name of unit test.

By adopting an appropriate test naming strategy, this allows user to run (or
to skip if `--skip` is used) whole groups of related tests with a single
command line argument. For example consider test suite `test_example` which
implements tests `foo-1`, `foo-2`, `foomatic`, `bar-1` and `bar-10`:

```sh
$ ./test_example bar-1   # Runs only the test 'bar-1' (exact match)
$ ./test_example foo     # Runs 'foo-1' and 'foo-2' (word match)
$ ./test_example oo      # Runs 'foo-1', 'foo-2' and 'foomatic' (relaxed match)
$ ./test_example 1       # Runs 'foo-1' and 'bar-1' (word match)
```

You may use `--list` or `-l` to just list all unit tests implemented by the
given test suite:

```sh
$ ./test_example --list
```

To see all the supported command line options, run the binary with the option
`--help`:

```sh
$ ./test_example --help
```


## FAQ

**Q:** Wasn't this project known as "CUTest"?

**A:** Yes. It has been renamed as the original name was
[too much overloaded](https://github.com/mity/cutest/issues/6).


## License

Acutest is covered with MIT license, see the file `LICENSE.md` or beginning of
`"acutest.h"` for its full text.


## More Information

The project resides on github:

* http://github.com/mity/acutest

You can find the latest version of Acutest there, contribute with enhancements
or report bugs.

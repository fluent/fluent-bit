# Contributing to librdkafka

(This document is based on [curl's CONTRIBUTE.md](https://github.com/curl/curl/blob/master/docs/CONTRIBUTE.md) - thank you!)

This document is intended to offer guidelines on how to best contribute to the
librdkafka project. This concerns new features as well as bug fixes and
general improvements.

### License and copyright

When contributing with code, you agree to put your changes and new code under
the same license librdkafka is already using unless stated and agreed
otherwise.

When changing existing source code, you do not alter the copyright of the
original file(s). The copyright will still be owned by the original creator(s)
or those who have been assigned copyright by the original author(s).

By submitting a patch to the librdkafka, you are assumed to have the right
to the code and to be allowed by your employer or whatever to hand over that
patch/code to us. We will credit you for your changes as far as possible, to
give credit but also to keep a trace back to who made what changes. Please
always provide us with your full real name when contributing!

Official librdkafka project maintainer(s) assume ownership of all accepted
submissions.

## Write a good patch

### Follow code style

When writing C code, follow the code style already established in
the project. Consistent style makes code easier to read and mistakes less
likely to happen.

clang-format is used to check, and fix, the style for C/C++ files,
while flake8 and autopep8 is used for the Python scripts.

You should check the style before committing by running `make style-check-changed`
from the top-level directory, and if any style errors are reported you can
automatically fix them using `make style-fix-changed` (or just run
that command directly).

The Python code may need some manual fixing since autopep8 is unable to fix
all warnings reported by flake8, in particular it will not split long lines,
in which case a `  # noqa: E501` may be needed to turn off the warning.

See the end of this document for the C style guide to use in librdkafka.


### Write Separate Changes

It is annoying when you get a huge patch from someone that is said to fix 511
odd problems, but discussions and opinions don't agree with 510 of them - or
509 of them were already fixed in a different way. Then the person merging
this change needs to extract the single interesting patch from somewhere
within the huge pile of source, and that gives a lot of extra work.

Preferably, each fix that correct a problem should be in its own patch/commit
with its own description/commit message stating exactly what they correct so
that all changes can be selectively applied by the maintainer or other
interested parties.

Also, separate changes enable bisecting much better when we track problems
and regression in the future.

### Patch Against Recent Sources

Please try to make your patches against latest master branch.

### Test Cases

Bugfixes should also include a new test case in the regression test suite
that verifies the bug is fixed.
Create a new tests/00<freenumber>-<short_bug_description>.c file and
try to reproduce the issue in its most simple form.
Verify that the test case fails for earlier versions and passes with your
bugfix in-place.

New features and APIs should also result in an added test case.

Submitted patches must pass all existing tests.
For more information on the test suite see [tests/README.md]



## How to get your changes into the main sources

File a [pull request on github](https://github.com/edenhill/librdkafka/pulls)

Your change will be reviewed and discussed there and you will be
expected to correct flaws pointed out and update accordingly, or the change
risk stalling and eventually just get deleted without action. As a submitter
of a change, you are the owner of that change until it has been merged.

Make sure to monitor your PR on github and answer questions and/or
fix nits/flaws. This is very important. We will take lack of replies as a
sign that you're not very anxious to get your patch accepted and we tend to
simply drop such changes.

When you adjust your pull requests after review, please squash the
commits so that we can review the full updated version more easily
and keep history cleaner.

For example:

    # Interactive rebase to let you squash/fixup commits
    $ git rebase -i master

    # Mark fixes-on-fixes commits as 'fixup' (or just 'f') in the
    # first column. These will be silently integrated into the
    # previous commit, so make sure to move the fixup-commit to
    # the line beneath the parent commit.

    # Since this probably rewrote the history of previously pushed
    # commits you will need to make a force push, which is usually
    # a bad idea but works good for pull requests.
    $ git push --force origin your_feature_branch


### Write good commit messages

A short guide to how to write good commit messages.

    ---- start ----
    [area]: [short line describing the main effect] [(#issuenumber)]
           -- empty line --
    [full description, no wider than 72 columns that describe as much as
    possible as to why this change is made, and possibly what things
    it fixes and everything else that is related]
    ---- stop ----

Example:

    cgrp: Restart query timer on all heartbeat failures (#10023)

    If unhandled errors were received in HeartbeatResponse
    the cgrp could get stuck in a state where it would not
    refresh its coordinator.


**Important**: Rebase your PR branch on top of master (`git rebase -i master`)
               and squash interim commits (to make a clean and readable git history)
               before pushing. Use force push to keep your history clean even after
               the initial PR push.

**Note**: Good PRs with bad commit messages or messy commit history
          such as "fixed review comment", will be squashed up in
          to a single commit with a proper commit message.


### Add changelog

If the changes in the PR affects the end user in any way, such as for a user
visible bug fix, new feature, API or doc change, etc, a release changelog item
needs to be added to [CHANGELOG.md](CHANGELOG.md) for the next release.

Add a single line to the appropriate section (Enhancements, Fixes, ..)
outlining the change, an issue number (if any), and your name or GitHub
user id for attribution.

E.g.:
```
## Enhancements
 * Improve commit() async parameter documentation (Paul Nit, #123)
```



# librdkafka C style guide

## Function and globals naming

Use self-explanatory hierarchical snake-case naming.
Pretty much all symbols should start with `rd_kafka_`, followed by
their subsystem (e.g., `cgrp`, `broker`, `buf`, etc..), followed by an
action (e.g, `find`, `get`, `clear`, ..).


## Variable naming

For existing types use the type prefix as variable name.
The type prefix is typically the first part of struct member fields.
Example:

  * `rd_kafka_broker_t` has field names starting with `rkb_..`, thus broker
     variable names should be named `rkb`


For other types use reasonably concise but descriptive names.
`i` and `j` are typical int iterators.

## Variable declaration

Variables must be declared at the head of a scope, no in-line variable
declarations are allowed.

## Indenting

Use 8 spaces indent, same as the Linux kernel.
In emacs, use `c-set-style "linux`.
For C++, use Google's C++ style.

Fix formatting issues by running `make style-fix` prior to committing.


## Comments

Use `/* .. */` comments, not `// ..`

For functions, use doxygen syntax, e.g.:

    /**
     * @brief <short description>
     * ..
     * @returns <something..>
     */


Make sure to comment non-obvious code and situations where the full
context of an operation is not easily graspable.

Also make sure to update existing comments when the code changes.


## Line length

Try hard to keep line length below 80 characters, when this is not possible
exceed it with reason.


## Braces

Braces go on the same line as their enveloping statement:

    int some_func (..) {
      while (1) {
        if (1) {
          do something;
          ..
        } else {
          do something else;
          ..
        }
      }

      /* Single line scopes should not have braces */
      if (1)
        hi();
      else if (2)
        /* Say hello */
        hello();
      else
        bye();


## Spaces

All expression parentheses should be prefixed and suffixed with a single space:

    int some_func (int a) {

        if (1)
          ....;

        for (i = 0 ; i < 19 ; i++) {


        }
    }


Use space around operators:

    int a = 2;

    if (b >= 3)
       c += 2;

Except for these:

    d++;
    --e;


## New block on new line

New blocks should be on a new line:

    if (1)
      new();
    else
      old();


## Parentheses

Don't assume the reader knows C operator precedence by heart for complex
statements, add parentheses to ease readability.


## ifdef hell

Avoid ifdef's as much as possible.
Platform support checking should be performed in configure.librdkafka.





# librdkafka C++ style guide

Follow [Google's C++ style guide](https://google.github.io/styleguide/cppguide.html)

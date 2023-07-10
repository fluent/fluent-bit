<!-- Provide summary of changes -->

<!-- Issue number, if available. E.g. "Fixes #31", "Addresses #42, #77" -->

----
Enter `[N/A]` in the box, if an item is not applicable to your change.

**Testing**
Before we can approve your change; please submit the following in a comment:
- [ ] Example configuration file for the change
- [ ] Debug log output from testing the change
<!--  
Please refer to the Developer Guide for instructions on building Fluent Bit with Valgrind support: 
https://github.com/fluent/fluent-bit/blob/master/DEVELOPER_GUIDE.md#valgrind
Invoke Fluent Bit and Valgrind as: $ valgrind --leak-check=full ./bin/fluent-bit <args>
-->
- [ ] Attached [Valgrind](https://valgrind.org/docs/manual/quick-start.html) output that shows no leaks or memory corruption was found

If this is a change to packaging of containers or native binaries then please confirm it works for all targets.
- [ ] Run [local packaging test](./packaging/local-build-all.sh) showing all targets (including any new ones) build.
- [ ] Set `ok-package-test` label to test for all targets (requires maintainer to do).

**Documentation**
<!-- Docs can be edited at https://github.com/fluent/fluent-bit-docs -->
- [ ] Documentation required for this feature

<!--  Doc PR (not required but highly recommended) -->

**Backporting**
<!--
PRs targeting the default master branch will go into the next major release usually.
If this PR should be backported to the current or earlier releases then please submit a PR for that particular branch.
-->
- [ ] Backport to latest stable release.

<!--  Other release PR (not required but highly recommended for quick turnaround) -->
----

Fluent Bit is licensed under Apache 2.0, by submitting this pull request I understand that this code will be released under the terms of that license.

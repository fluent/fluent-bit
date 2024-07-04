## c-ares version 1.32.0 - July 4 2024

This is a feature and bugfix release.

Features:

* Add support for DNS 0x20 to help prevent cache poisoning attacks, enabled
  by specifying `ARES_FLAG_DNS0x20`.  Disabled by default. [PR #800](https://github.com/c-ares/c-ares/pull/800)
* Rework query timeout logic to automatically adjust timeouts based on network
  conditions.  The timeout specified now is only used as a hint until there
  is enough history to calculate a more valid timeout. [PR #794](https://github.com/c-ares/c-ares/pull/794)

Changes:

* DNS RR TXT strings should not be automatically concatenated as there are use
  cases outside of RFC 7208.  In order to maintain ABI compliance, the ability
  to retrieve TXT strings concatenated is retained as well as a new API to
  retrieve the individual strings.  This restores behavior from c-ares 1.20.0.
  [PR #801](https://github.com/c-ares/c-ares/pull/801)
* Clean up header inclusion logic to make hacking on code easier. [PR #797](https://github.com/c-ares/c-ares/pull/797)
* GCC/Clang: Enable even more strict warnings to catch more coding flaws. [253bdee](https://github.com/c-ares/c-ares/commit/253bdee)
* MSVC: Enable `/W4` warning level. [PR #792](https://github.com/c-ares/c-ares/pull/792)

Bugfixes:

* Tests: Fix thread race condition in test cases for EventThread. [PR #803](https://github.com/c-ares/c-ares/pull/803)
* Windows: Fix building with UNICODE. [PR #802](https://github.com/c-ares/c-ares/pull/802)
* Thread Saftey: `ares_timeout()` was missing lock. [74a64e4](https://github.com/c-ares/c-ares/commit/74a64e4)
* Fix building with DJGPP (32bit protected mode DOS). [PR #789](https://github.com/c-ares/c-ares/pull/789)

Thanks go to these friendly people for their efforts and contributions for this
release:

* Brad House (@bradh352)
* Cheng (@zcbenz)




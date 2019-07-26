# Fork of libco for Fluent Bit

This repository is a fork of the original library [libco](https://byuu.org/library/libco/) v18 created by Byuu. Compared to the original version it have the following changes:

- Core
  - ARMv8: workaround for [GCC bug](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90907).
  - Added [aarch64.c](aarch64.c) backend file created by [webgeek1234](https://github.com/webgeek1234).
  - Fixes on settings.h to get MacOS support.
- API
  - co_create() have a third argument to retrieve the real size of the stack created.

This library is used inside [Fluent Bit](http://github.com/fluent/fluent-bit) project, so this repo aims to keep aligned with latest releases but including our required patches.

Eduardo Silva <eduardo@monkey.io>

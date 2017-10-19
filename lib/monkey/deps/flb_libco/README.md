# Modified libco from byuu.org for Fluent Bit

This repository is a mirror from [libco](https://byuu.org/library/libco/) v18 plus some additional patches:

- co_create() have a third argument to retrieve the real size of the stack created.
- settings.h modified so libco can work on OSX.

This library is used inside [Fluent Bit](http://github.com/fluent/fluent-bit) project, so this repo aims to keep aligned with latest releases but including our required patches.

Eduardo Silva <eduardo@monkey.io>

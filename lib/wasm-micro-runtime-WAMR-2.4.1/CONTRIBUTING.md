Contributing to WAMR
=====================
As an open-source project, we welcome and encourage the community to submit patches directly to the project. In our collaborative open source environment, standards and methods for submitting changes help reduce the chaos that can result from an active development community.
We want to make contributing to this project as easy and transparent as possible, whether it's:
- Reporting a bug
- the current state of the code
- Submitting a fix
- Proposing new features

License
=======
WAMR uses the same license as LLVM: the `Apache 2.0 license` with the LLVM
exception. See the LICENSE file for details. This license allows you to freely
use, modify, distribute and sell your own products based on WAMR.
Any contributions you make will be under the same license.

Code changes
===================
We Use Github Flow, So All Code Changes Happen Through Pull Requests. Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

- If you've added code that should be tested, add tests. Ensure the test suite passes.
- Avoid use macros for different platforms. Use separate folder of source files to host different platform logic.
- Put macro definitions inside share_lib/include/config.h if you have to use macro.
- Make sure your code lints and compliant to our coding style.
- Extend the application library is highly welcome.

Coding Style
===============================
Please use [K&R](https://en.wikipedia.org/wiki/Indentation_style#K.26R) coding style, such as 4 spaces for indentation rather than tabs etc.
We suggest using VS Code like IDE or stable coding format tools, like clang-format, to make your code compliant to the customized format(in .clang-format).

Report bugs
===================
We use GitHub issues to track public bugs. Report a bug by [open a new issue](https://github.com/intel/wasm-micro-runtime/issues/new).

Code of Conduct
===============

WAMR is a [Bytecode Alliance](https://bytecodealliance.org/) project, and follows the Bytecode Alliance's [Code of Conduct](CODE_OF_CONDUCT.md) and [Organizational Code of Conduct](ORG_CODE_OF_CONDUCT.md).

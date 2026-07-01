Contribution Guidelines
=======================

[This text was composed based on 1.2. License section of curl/libcurl
project.]

When contributing with code, you agree to put your changes and new
code under the same license nghttp2 is already using unless stated and
agreed otherwise.

When changing existing source code, you do not alter the copyright of
the original file(s).  The copyright will still be owned by the
original creator(s) or those who have been assigned copyright by the
original author(s).

By submitting a patch to the nghttp2 project, you are assumed to have
the right to the code and to be allowed by your employer or whatever
to hand over that patch/code to us.  We will credit you for your
changes as far as possible, to give credit but also to keep a trace
back to who made what changes.  Please always provide us with your
full real name when contributing!

Coding style
------------

We use clang-format to format source code consistently.  The
clang-format configuration file .clang-format is located at the root
directory.  Since clang-format produces slightly different results
between versions, we currently use clang-format-18.

To detect any violation to the coding style, we recommend to setup git
pre-commit hook to check coding style of the changes you introduced.
The pre-commit file is located at the root directory.  Copy it under
.git/hooks and make sure that it is executable.  The pre-commit script
uses clang-format-diff.py to detect any style errors.  If it is not in
your PATH or it exists under different name (e.g.,
clang-format-diff-18 in debian), either add it to PATH variable or add
git option ``clangformatdiff.binary`` to point to the script.

For emacs users, integrating clang-format to emacs is very easy.
clang-format.el should come with clang distribution.  If it is not
found, download it from `here
<https://github.com/llvm/llvm-project/blob/main/clang/tools/clang-format/clang-format.el>`_.
And add these lines to your .emacs file:

.. code-block:: lisp

    ;; From
    ;; https://code.google.com/p/chromium/wiki/Emacs#Use_Google's_C++_style!
    (load "/<path/to>/clang-format.el")
    (add-hook 'c-mode-common-hook
         (function (lambda () (local-set-key (kbd "TAB")
                                             'clang-format-region))))

You can find other editor integration in
http://clang.llvm.org/docs/ClangFormat.html.

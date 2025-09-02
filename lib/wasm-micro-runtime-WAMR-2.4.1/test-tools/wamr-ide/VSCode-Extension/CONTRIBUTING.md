# CONTRIBUTING

## Pull requests

To submit your change:

-   Make sure your code is in line with our
    [coding conventions](##Coding-conventions).
-   Create an [issue] describing the bug the PR fixes or the feature you intend
    to implement.
-   Submit a [pull request] into the main branch.

## Coding conventions

#### Format

The codebase is formatted by `Prettier` and the `.prettierrc.json` has been
configured.

-   VSCode along with `Format on Save` configuration could easily format your
    code during development.
-   You can run `prettier-format-check` and `prettier-format-apply` to check and
    format your codebase with `prettier` in terminal.

#### Lint

`ESlint` is used as linter for the codebase and the `.eslintrc.json` has been
configured.

-   It's suggested to run `npm run lint` then fix errors and warnings before
    committing.

[issue]: https://github.com/bytecodealliance/wasm-micro-runtime/issues
[pull request]: https://github.com/bytecodealliance/wasm-micro-runtime/pulls

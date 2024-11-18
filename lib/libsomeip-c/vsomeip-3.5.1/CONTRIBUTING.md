# Contributing to vsomeip-lib

All types of contributions are encouraged and valued.

## Did you find a bug?

- **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/COVESA/vsomeip/issues).

- If you cannot find an existing open issue addressing the problem, feel free to create a new one [here](https://github.com/COVESA/vsomeip/issues/new). Make sure to provide a descriptive **title, a clear explanation of the issue, relevant information**, and if possible, include a code sample or a test case demonstrating the expected behavior that is not occurring.

## Styleguides

We prioritize consistency and maintainability in our code bases. To achieve this, we have established comprehensive coding standards encompassing general style guidelines and specific configurations for Clang-Format integration.

Explore the [Table of Contents](#table-of-contents) to discover various paths for assistance and comprehensive insights into our coding standards.

### Table of Contents

- [General Guidelines](#general-guidelines)

- [Naming Conventions](#naming-conventions)

- [Clang Format Integration](#clang-format-integration)

  - [Based Style](#based-style)

  - [Standard](#standard)

  - [Clang-Format Customization](#clang-format-customization)

  - [How to use Clang Format](#how-to-use-clang-format)

  - [Workflow Summary](#workflow-summary)

- [Showcase of good and bad practice](#showcase-of-good-and-bad-practice)

### General Guidelines

Before submitting a pull request, please ensure that you adhere to the following coding guidelines.

### Naming Conventions

Maintaining a consistent naming convention enhances code readability and comprehension. Our naming conventions dictate the following:
   - **Arguments:** Argument names should start with an underscore.

   - **Members:** Member variables should end with an underscore.

   - **Local Variables:** Local variables neither start nor end with an underscore.

   - **Static Variables:** Static variables should end with two underscores.

### Clang Format Integration

Incorporating Clang Format into our projects is integral to ensuring uniform and readable code formatting. Clang Format is a powerful tool that automatically formats C, C++, and Objective-C code based on predefined style guidelines.

#### Based Style

```yaml
BasedOnStyle: WebKit
```
Our code style is based on the WebKit style, which is in turn influenced by the Qt style.

Webkit style guidelines can be found here [Webkit.org](https://www.webkit.org/code-style-guidelines/)

#### Standard

```yaml
Standard: c++17
```
The C++ standard to be used, in this case, C++17.

Below is the configuration option used in our Clang Format setup:

#### Clang-Format Customization

```yaml
BasedOnStyle: WebKit
Standard: c++17
ColumnLimit: 100
PointerAlignment: Left
SpaceAfterTemplateKeyword: false
BreakBeforeBinaryOperators: NonAssignment
BreakBeforeBraces: Attach
ConstructorInitializerIndentWidth: 4
ContinuationIndentWidth: 8
Cpp11BracedListStyle: true
NamespaceIndentation: None
IndentPPDirectives: AfterHash
AlignAfterOpenBracket: true
AlwaysBreakTemplateDeclarations: true
AllowShortFunctionsOnASingleLine: Inline
SortIncludes: false
BreakConstructorInitializers: AfterColon
```

#### How to use Clang Format

Formatting your code using Clang Format is seamlessly integrated into the development workflow through [pre-commit-hooks](https://github.com/pocc/pre-commit-hooks). Follow these steps to set it up:

#### Step 1: Install `pre-commit`

```
pip install pre-commit
```

#### Step 2: Navigate to the project's root directory

```
cd vsomeip-lib
```

#### Step 3: Install the pre-commit hook

```
pre-commit install
```

Now, every time you commit staged changes, Clang Format will automatically be invoked to format your code. This is achieved through the pre-commit hook.

#### Workflow Summary

1. **Make your code changes**
   - Implement the desired changes in your code.

2. **Stage the changes using `git add`**
   - Use `git add` to stage the modifications you want to commit.

3. **Commit changes with `git commit`**
   - When you run `git commit`, Clang Format will automatically be applied to the staged changes before the commit is finalized.

This seamless integration ensures consistent code formatting as part of the development workflow. Developers can focus on writing code, and the pre-commit hook takes care of formatting during the commit process.

### Showcase of good and bad practice

This code snippet was taken from `vsomeip-lib/implementation/routing/src/routing_manager_impl.cpp `.

#### Good Practice

```c++
void routing_manager_impl::init() {
    routing_manager_base::init(ep_mgr_impl_);
    if (configuration_->is_routing_enabled()) {
        stub_ = std::make_shared<routing_manager_stub>(this, configuration_);
        stub_->init();
    } else {
        // Good Practice: Proper indentation and spacing.
        VSOMEIP_INFO << "Internal message routing disabled!";
    }
    // Good Practice: Proper spacing and indentation.
    if (configuration_->is_sd_enabled()) {
        // Good Practice: Proper spacing and alignment.
        VSOMEIP_INFO << "Service Discovery enabled. Trying to load module.";
        auto its_plugin = plugin_manager::get()->get_plugin(
            plugin_type_e::SD_RUNTIME_PLUGIN, VSOMEIP_SD_LIBRARY);
        if (its_plugin) {
            // Good Practice: Braces attached to the preceding line, consistent spacing.
            VSOMEIP_INFO << "Service Discovery module loaded.";
            discovery_ = std::dynamic_pointer_cast<sd::runtime>(its_plugin)
                             ->create_service_discovery(this, configuration_);
            discovery_->init();
        } else {
            // Good Practice: Proper indentation and spacing.
            VSOMEIP_ERROR << "Service Discovery module could not be loaded!";
            std::exit(EXIT_FAILURE);
        }
    }
}
```

#### Bad Practice

```c++
void routing_manager_impl::init()
{
    routing_manager_base::init(ep_mgr_impl_);
    // Bad Practice: Inconsistent indentation and brace placement.
    if (configuration_-> is_routing_enabled())
    {
        stub_ = std::make_shared<routing_manager_stub>(this, configuration_);
        stub_->init();
    }
    else
    {
        // Bad Practice: Inconsistent indentation and lack of space after binary operators.
        VSOMEIP_INFO
            << "Internal message routing disabled!";
    }
    // Bad Practice: Lack of proper spacing and alignment.
    if (configuration_->is_sd_enabled())
    {
        // Bad Practice: Inconsistent indentation and spacing.
        VSOMEIP_INFO << "Service Discovery enabled. Trying to load module.";
        auto its_plugin = plugin_manager::get()->get_plugin(
            plugin_type_e::SD_RUNTIME_PLUGIN, VSOMEIP_SD_LIBRARY); if (its_plugin) {VSOMEIP_INFO
                    << "Service Discovery module loaded.";
            discovery_ = std::dynamic_pointer_cast<sd::runtime>(its_plugin)->create_service_discovery(this, configuration_);discovery_->init();
         }
        else {VSOMEIP_ERROR
              << "Service Discovery module could not be loaded!";
              std::exit(EXIT_FAILURE);}
   }
}
```

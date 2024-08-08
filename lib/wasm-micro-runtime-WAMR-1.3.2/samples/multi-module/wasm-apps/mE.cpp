#include <cstdlib>
#include <cstdio>
#include <iostream>

static void
bye_setup()
{
    std::cout << "mE " << __FUNCTION__ << std::endl;
}

static void
bye_func()
{
    std::cout << "mE " << __FUNCTION__ << std::endl;
}

__attribute__((constructor)) void
setup()
{
    std::cout << "mE " << __FUNCTION__ << std::endl;
    if (std::atexit(bye_setup) != 0) {
        std::perror("register an atexit handler failed");
    }
}

__attribute__((destructor)) void
teardown()
{
    std::cout << "mE " << __FUNCTION__ << std::endl;
}

__attribute__((export_name("func1"))) void
func1()
{
    std::cout << "mE " << __FUNCTION__ << std::endl;
    if (std::atexit(bye_func) != 0) {
        std::perror("register an atexit handler failed");
    }
}

__attribute__((export_name("func2"))) void
func2()
{
    std::cout << "mE " << __FUNCTION__ << std::endl;
}

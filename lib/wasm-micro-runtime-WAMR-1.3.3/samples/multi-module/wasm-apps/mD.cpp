#include <cstdlib>
#include <cstdio>
#include <iostream>

static void
bye_main()
{
    std::cout << "mD " << __FUNCTION__ << std::endl;
}

static void
bye_setup()
{
    std::cout << "mD " << __FUNCTION__ << std::endl;
}

static void
bye_func()
{
    std::cout << "mD " << __FUNCTION__ << std::endl;
}

void
func3() __attribute__((__import_module__("mE"), __import_name__("func1")));

void
func4() __attribute__((__import_module__("mE"), __import_name__("func2")));

void
func1()
{
    std::printf("mD %s\n", __FUNCTION__);
    if (std::atexit(bye_func) != 0) {
        std::perror("register an atexit handler failed");
    }
    func3();
}

void
func2()
{
    std::printf("mD %s\n", __FUNCTION__);
    func4();
}

__attribute__((constructor)) void
setup()
{
    std::cout << "mD " << __FUNCTION__ << std::endl;
    if (std::atexit(bye_setup) != 0) {
        std::perror("register an atexit handler failed");
    }
}

__attribute__((destructor)) void
teardown()
{
    std::cout << "mD " << __FUNCTION__ << std::endl;
}

int
main()
{
    std::printf("mD %s\n", __FUNCTION__);

    if (std::atexit(bye_main) != 0) {
        std::perror("register an atexit handler failed");
        return EXIT_FAILURE;
    }

    func1();
    func2();
    return EXIT_SUCCESS;
}

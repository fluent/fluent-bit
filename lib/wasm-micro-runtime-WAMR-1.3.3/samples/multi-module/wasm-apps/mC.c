#include <stdio.h>
#include <stdlib.h>

__attribute__((import_module("mA")))
__attribute__((import_name("A1"))) extern int
A1();

__attribute__((import_module("mB")))
__attribute__((import_name("B1"))) extern int
B1();

__attribute__((import_module("mB")))
__attribute__((import_name("B2"))) extern int
B2();

__attribute__((export_name("C1"))) int
C1()
{
    return 31;
}

__attribute__((export_name("C2"))) int
C2()
{
    return B1();
}

__attribute__((export_name("C3"))) int
C3()
{
    return A1();
}

__attribute__((export_name("C4"))) int
C4()
{
    return B2();
}

int
C5()
{
    return C1() + C2() + C3() + 35;
}

int
main()
{
    printf("%u\n", C5());
    return EXIT_SUCCESS;
}
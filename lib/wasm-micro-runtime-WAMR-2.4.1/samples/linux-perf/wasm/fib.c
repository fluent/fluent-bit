#include <stdio.h>
#include <stdlib.h>

int
fibonacci(int n)
{
    if (n <= 0)
        return 0;

    if (n == 1)
        return 1;

    return fibonacci(n - 1) + fibonacci(n - 2);
}

__attribute__((export_name("run"))) int
run(int n)
{
    int result = fibonacci(n);
    printf("fibonacci(%d)=%d\n", n, result);
    return result;
}

int
main(int argc, char **argv)
{
    int n = atoi(argv[1]);

    printf("fibonacci(%d)=%d\n", n, fibonacci(n));

    return 0;
}

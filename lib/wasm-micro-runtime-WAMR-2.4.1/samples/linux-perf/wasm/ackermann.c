#include <stdio.h>

// Ackermann function
unsigned long
ackermann(unsigned long m, unsigned long n)
{
    if (m == 0) {
        return n + 1;
    }
    else if (n == 0) {
        return ackermann(m - 1, 1);
    }
    else {
        return ackermann(m - 1, ackermann(m, n - 1));
    }
}

__attribute__((export_name("run"))) int
run(int m, int n)
{
    int result = ackermann(m, n);
    printf("ackermann(%d, %d)=%d\n", m, n, result);
    return result;
}

int
main()
{
    unsigned long m, n, result;

    // Example usage:
    m = 3;
    n = 2;
    result = ackermann(m, n);
    printf("Ackermann(%lu, %lu) = %lu\n", m, n, result);

    return 0;
}

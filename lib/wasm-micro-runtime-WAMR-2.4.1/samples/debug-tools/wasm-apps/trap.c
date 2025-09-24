int
c(int n)
{
    __builtin_trap();
}

int
b(int n)
{
    n += 3;
    return c(n);
}

int
a(int n)
{
    return b(n);
}

int
main(int argc, char **argv)
{
    int i = 5;
    a(i);

    return 0;
}

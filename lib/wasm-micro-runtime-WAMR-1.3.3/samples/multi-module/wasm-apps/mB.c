__attribute__((import_module("mA")))
__attribute__((import_name("A1"))) extern int
A1();

__attribute__((export_name("B1"))) int
B1()
{
    return 21;
}

__attribute__((export_name("B2"))) int
B2()
{
    return A1();
}

int
B3()
{
    return 23;
}

/* mA is a  reactor. it doesn't need a main() */
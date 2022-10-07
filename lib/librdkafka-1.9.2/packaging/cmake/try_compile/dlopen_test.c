#include <string.h>
#include <dlfcn.h>

int main() {
        void *h;
        /* Try loading anything, we don't care if it works */
        h = dlopen("__nothing_rdkafka.so", RTLD_NOW | RTLD_LOCAL);
        if (h)
                dlclose(h);
        return 0;
}

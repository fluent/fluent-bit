#include <inttypes.h>

int64_t foo(int64_t i) {
        return __atomic_add_fetch(&i, 1, __ATOMIC_SEQ_CST);
}

int main() {
}

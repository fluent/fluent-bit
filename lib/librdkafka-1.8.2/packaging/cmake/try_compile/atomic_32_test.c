#include <inttypes.h>

int32_t foo (int32_t i) {
  return __atomic_add_fetch(&i, 1, __ATOMIC_SEQ_CST);
}

int main() {
}

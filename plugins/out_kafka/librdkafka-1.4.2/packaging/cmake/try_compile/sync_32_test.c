#include <inttypes.h>

int32_t foo (int32_t i) {
  return __sync_add_and_fetch(&i, 1);
}

int main() {
}

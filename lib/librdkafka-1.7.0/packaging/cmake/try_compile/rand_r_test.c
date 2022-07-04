#include <stdlib.h>

int main() {
   unsigned int seed = 0xbeaf;
   (void)rand_r(&seed);
   return 0;
}

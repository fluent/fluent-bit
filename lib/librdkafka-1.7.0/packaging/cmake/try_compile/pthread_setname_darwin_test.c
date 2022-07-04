#include <pthread.h>

int main() {
  pthread_setname_np("abc");
  return 0;
}

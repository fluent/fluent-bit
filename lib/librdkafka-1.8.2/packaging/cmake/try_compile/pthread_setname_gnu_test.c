#include <pthread.h>

int main() {
   return pthread_setname_np(pthread_self(), "abc");
}

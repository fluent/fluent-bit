#include <unistd.h>
#include <sys/random.h>

int main() {
        char seed[16];
        return getentropy(seed, sizeof(seed));
}

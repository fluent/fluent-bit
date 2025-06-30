#include <string.h>

int main() {
        return strndup("hi", 2) ? 0 : 1;
}

#include <stddef.h>
#include <regex.h>

int main() {
        regcomp(NULL, NULL, 0);
        regexec(NULL, NULL, 0, NULL, 0);
        regerror(0, NULL, NULL, 0);
        regfree(NULL);
        return 0;
}

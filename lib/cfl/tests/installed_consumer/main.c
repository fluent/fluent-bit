#include <stdint.h>
#include <string.h>

#include <cfl/cfl.h>

int main(void)
{
    int result;
    uint64_t hash;
    struct cfl_array *array;

    result = cfl_init();
    if (result != 0) {
        return 1;
    }

    if (cfl_version() == NULL) {
        return 1;
    }

    array = cfl_array_create(1);
    if (array == NULL) {
        return 1;
    }

    result = cfl_array_append_string(array, "installed");
    if (result != 0 || cfl_array_size(array) != 1) {
        cfl_array_destroy(array);
        return 1;
    }

    hash = cfl_hash_64bits("installed", strlen("installed"));
    cfl_array_destroy(array);

    if (hash == 0) {
        return 1;
    }

    return 0;
}

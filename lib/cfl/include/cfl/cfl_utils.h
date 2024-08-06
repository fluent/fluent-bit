#ifndef CFL_UTILS_H
#define CFL_UTILS_H

#include <sys/types.h> /* off_t */
#include <cfl/cfl_sds.h>
#include <cfl/cfl_compat.h>

struct cfl_split_entry {
    char *value;
    int len;
    off_t last_pos;
    struct cfl_list _head;
};

struct cfl_list *cfl_utils_split_quoted(const char *line, int separator, int max_split);
struct cfl_list *cfl_utils_split(const char *line, int separator, int max_split);
void cfl_utils_split_free_entry(struct cfl_split_entry *entry);
void cfl_utils_split_free(struct cfl_list *list);

#endif

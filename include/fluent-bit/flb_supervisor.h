#ifndef FLB_SUPERVISOR_H
#define FLB_SUPERVISOR_H

#include <fluent-bit/flb_info.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*flb_supervisor_entry_fn)(int argc, char **argv);

int flb_supervisor_requested(int argc, char **argv);
int flb_supervisor_run(int argc, char **argv, flb_supervisor_entry_fn entry);
void flb_supervisor_child_update_grace(int grace, int grace_input);
void flb_supervisor_child_signal_shutdown(int grace, int grace_input);

#ifdef __cplusplus
}
#endif

#endif

#ifndef TRACE_TRACES_H
#define TRACE_TRACES_H

#include <bpf/libbpf.h>

#include "generated/trace_signal.skel.h"
#include "generated/trace_malloc.skel.h"
#include "generated/trace_bind.skel.h"

#include "bind/handler.h"
#include "signal/handler.h"  // Include signal handler
#include "malloc/handler.h" // Include malloc handler

/* Skeleton function pointer types */
typedef void *(*trace_skel_open_func_t)(void);
typedef int (*trace_skel_attach_func_t)(void *);
typedef void (*trace_skel_destroy_func_t)(void *);
typedef struct bpf_object *(*trace_skel_get_bpf_object_func_t)(void *);

/* Event handler function pointer type */
typedef int (*trace_event_handler_t)(void *ctx, void *data, size_t data_sz);

/* Structure for managing trace handlers and their contexts */
struct trace_context {
    const char *name;
    struct ring_buffer *rb;
    struct bpf_object *obj;
    trace_event_handler_t handler;
};

struct trace_registration {
    const char *name;
    trace_event_handler_t handler;
    trace_skel_open_func_t skel_open;
    trace_skel_attach_func_t skel_attach;
    trace_skel_destroy_func_t skel_destroy;
    trace_skel_get_bpf_object_func_t skel_get_bpf_object;
};

/* Macro to define get_bpf_object function */
#define DEFINE_GET_BPF_OBJECT(trace_name)                                   \
    struct bpf_object *trace_name##__get_bpf_object(struct trace_name *skel) { \
        return skel->obj;                                                   \
    }

/* Macro to register the trace in the trace_table */
#define REGISTER_TRACE(trace_name, handler_func)                            \
    {                                                                       \
        #trace_name,                                                        \
        handler_func,                                                       \
        (trace_skel_open_func_t)trace_name##__open_and_load,                \
        (trace_skel_attach_func_t)trace_name##__attach,                     \
        (trace_skel_destroy_func_t)trace_name##__destroy,                   \
        (trace_skel_get_bpf_object_func_t)trace_name##__get_bpf_object      \
    }

/* Define the get_bpf_object function for each trace */
DEFINE_GET_BPF_OBJECT(trace_signal)
DEFINE_GET_BPF_OBJECT(trace_malloc)
DEFINE_GET_BPF_OBJECT(trace_bind)

static struct trace_registration trace_table[] = {
    REGISTER_TRACE(trace_signal, trace_signal_handler),
    REGISTER_TRACE(trace_malloc, trace_malloc_handler),
    REGISTER_TRACE(trace_bind, trace_bind_handler),
};

#endif // TRACE_TRACES_H

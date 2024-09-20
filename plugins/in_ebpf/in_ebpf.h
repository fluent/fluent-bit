/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef FLB_IN_EBPF_H
#define FLB_IN_EBPF_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

/* Define default values */
#define FLB_IN_EBPF_DEFAULT_RINGBUF_MAP_NAME  "events"
#define FLB_IN_EBPF_DEFAULT_POLL_MS           "1000"  // 1 second default poll timeout
#define FLB_IN_EBPF_DEFAULT_ATTRIBUTE_NAME    "payload"
#define FLB_IN_EBPF_DEFAULT_RINGBUF_SIZE      "8192"  // Default ring buffer size in bytes

#define MAX_EVENT_LEN 128

/* Configuration structure for eBPF plugin */
struct flb_in_ebpf_config {
    struct ring_buffer *rb;
    struct bpf_object *obj;
    struct flb_log_event_encoder *log_encoder; // Log encoder
    int map_fd;
    size_t ringbuf_size;
    size_t ringbuf_consume_count; /* events to consume from ring buffer on each poll */
    char *ringbuf_map_name;
    int poll_ms;   /* Poll timeout in milliseconds */
    const char *bpf_object_file;  /* Path to the eBPF object file */
    const char *bpf_program_name; /* Name of the eBPF program to attach */
    char *attribute_name;  /* Configurable attribute name */
    int coll_fd; /* Collector file descriptor */
    struct flb_input_instance *ins; /* Pointer to the input instance */
};

/* Event types enum in UPPERCASE */
enum FLB_IN_EBPF_EVENT_TYPE {
    FLB_IN_EBPF_EVENT_FILESYSTEM = 0,
    FLB_IN_EBPF_EVENT_NETWORK = 1,
    FLB_IN_EBPF_EVENT_PROCESS = 2
};

/* Event structure sent by eBPF */
struct flb_in_ebpf_event {
    __u32 pid;
    __u32 event_type;            // Event type as an enum
    char data[MAX_EVENT_LEN];     // Event-specific data (filename, network info, etc.)
};

/* Define constant strings for event types */
#define FLB_IN_EBPF_EVENT_TYPE_FILESYSTEM  "filesystem"
#define FLB_IN_EBPF_EVENT_TYPE_NETWORK     "network"
#define FLB_IN_EBPF_EVENT_TYPE_PROCESS     "process"
#define FLB_IN_EBPF_EVENT_TYPE_UNKNOWN     "unknown"

/* Function to map enum values to strings */
static inline const char *get_event_type_str(int event_type) {
    switch (event_type) {
        case FLB_IN_EBPF_EVENT_FILESYSTEM:
            return FLB_IN_EBPF_EVENT_TYPE_FILESYSTEM;
        case FLB_IN_EBPF_EVENT_NETWORK:
            return FLB_IN_EBPF_EVENT_TYPE_NETWORK;
        case FLB_IN_EBPF_EVENT_PROCESS:
            return FLB_IN_EBPF_EVENT_TYPE_PROCESS;
        default:
            return FLB_IN_EBPF_EVENT_TYPE_UNKNOWN;
    }
}

int handle_ebpf_event(void *instance, void *data, size_t data_sz);
int encode_log_event(struct flb_input_instance *ins,
                     struct flb_log_event_encoder *log_encoder,
                     const char *event_type_str,
                     __u32 pid,
                     const char *data, size_t data_len);
int extract_event_data(void *data, size_t data_sz, const char **event_type_str,
                       __u32 *pid, char **event_data, size_t *event_data_len);
#endif /* FLB_IN_EBPF_H */

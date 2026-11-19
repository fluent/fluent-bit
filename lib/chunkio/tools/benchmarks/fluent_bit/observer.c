/* Benchmark-only linker wrappers; production sources are unchanged. */
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/resource.h>

struct cio_file;
struct flb_input_instance;
static atomic_ulong remaps;
static atomic_ulong resizes;
static atomic_ulong maps;
static size_t appended;
static size_t calls;
static double first_wall;
static double first_cpu;
static double last_wall;
static double last_cpu;

static double seconds(clockid_t clock)
{
    struct timespec value;

    clock_gettime(clock, &value);
    return value.tv_sec + value.tv_nsec / 1000000000.0;
}

int __real_cio_file_native_remap(struct cio_file *, size_t);
int __wrap_cio_file_native_remap(struct cio_file *file, size_t size)
{
    atomic_fetch_add(&remaps, 1);
    return __real_cio_file_native_remap(file, size);
}

int __real_cio_file_native_resize(struct cio_file *, size_t);
int __wrap_cio_file_native_resize(struct cio_file *file, size_t size)
{
    atomic_fetch_add(&resizes, 1);
    return __real_cio_file_native_resize(file, size);
}

int __real_cio_file_native_map(struct cio_file *, size_t);
int __wrap_cio_file_native_map(struct cio_file *file, size_t size)
{
    atomic_fetch_add(&maps, 1);
    return __real_cio_file_native_map(file, size);
}

int __real_flb_input_log_append_records(struct flb_input_instance *, size_t,
                                       const char *, size_t, const void *, size_t);
int __wrap_flb_input_log_append_records(struct flb_input_instance *input,
                                       size_t records, const char *tag,
                                       size_t tag_length, const void *buffer,
                                       size_t length)
{
    int result;
    FILE *file;

    if (calls == 0) {
        first_wall = seconds(CLOCK_MONOTONIC);
        first_cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
    }
    calls++;
    result = __real_flb_input_log_append_records(input, records, tag, tag_length,
                                                buffer, length);
    if (result == 0) {
        appended += records;
    }
    if (appended == strtoull(getenv("BENCH_RECORDS"), NULL, 10)) {
        last_wall = seconds(CLOCK_MONOTONIC);
        last_cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
        file = fopen(getenv("BENCH_READY"), "w");
        if (file) {
            fprintf(file, "{\"ingest_seconds\":%.9f,\"ingest_cpu_seconds\":%.9f,"
                    "\"records\":%zu,\"append_calls\":%zu}\n",
                    last_wall - first_wall, last_cpu - first_cpu, appended, calls);
            fclose(file);
        }
    }
    return result;
}

__attribute__((destructor)) static void report(void)
{
    FILE *file;
    struct rusage usage;

    if (!getenv("BENCH_STATS")) {
        return;
    }
    getrusage(RUSAGE_SELF, &usage);
    file = fopen(getenv("BENCH_STATS"), "w");
    if (file) {
        fprintf(file, "{\"remaps\":%lu,\"resizes\":%lu,\"maps\":%lu,"
                "\"cpu_seconds\":%.6f,\"max_rss_kib\":%ld}\n",
                atomic_load(&remaps), atomic_load(&resizes), atomic_load(&maps),
                usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0 +
                usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0,
                usage.ru_maxrss);
        fclose(file);
    }
}

/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Benchmark for trace sampling hot paths.
 *
 * Modes:
 *   - probabilistic: calls sampling_probabilistic_plugin.cb_do_sampling()
 *   - tail-reconcile: uses tail sampling reconciliation (legacy/new)
 *
 * Usage example:
 *   flb-bench-processor_sampling --mode probabilistic --iterations 20000 \
 *       --spans-per-trace 20 --trace-cardinality 4096
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#include <ctraces/ctraces.h>
#include "../plugins/processor_sampling/sampling.h"
#include "../plugins/processor_sampling/sampling_span_registry.h"

enum bench_mode {
    MODE_PROBABILISTIC = 0,
    MODE_TAIL_RECONCILE
};

#ifdef FLB_SAMPLING_BENCH
int sampling_tail_bench_reconcile(struct sampling *ctx,
                                  struct sampling_span_registry *span_reg,
                                  int legacy_reconcile,
                                  int decision_wait,
                                  uint64_t *out_traces,
                                  uint64_t *out_spans);
#endif

/*
 * sampling_tail.c references these during link, but this benchmark does not
 * execute that pipeline path.
 */
__attribute__((weak))
int flb_input_trace_append_skip_processor_stages(struct flb_input_instance *ins,
                                                 size_t processor_starting_stage,
                                                 const char *tag, size_t tag_len,
                                                 struct ctrace *ctr)
{
    (void) ins;
    (void) processor_starting_stage;
    (void) tag;
    (void) tag_len;
    (void) ctr;
    return 0;
}

__attribute__((weak))
int sampling_conditions_check(struct sampling *ctx,
                              struct sampling_conditions *sampling_conditions,
                              struct trace_entry *trace_entry,
                              struct ctrace_span *span)
{
    (void) ctx;
    (void) sampling_conditions;
    (void) trace_entry;
    (void) span;
    return FLB_TRUE;
}

struct probabilistic_settings {
    int sampling_percentage;
};

static long diff_ns(struct timespec *s, struct timespec *e)
{
    return (long) (e->tv_sec - s->tv_sec) * 1000000000L + (long) (e->tv_nsec - s->tv_nsec);
}

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t x;

    x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;

    return x;
}

static void fill_id(uint8_t *buf, size_t len, uint64_t seed, uint64_t key, uint64_t salt)
{
    size_t i;
    uint64_t state;
    uint64_t n;

    state = seed ^ (key * 0x9e3779b97f4a7c15ULL) ^ (salt * 0x94d049bb133111ebULL);
    for (i = 0; i < len; i += sizeof(uint64_t)) {
        n = xorshift64(&state);
        memcpy(buf + i, &n, (len - i >= sizeof(uint64_t)) ? sizeof(uint64_t) : (len - i));
    }
}

static struct ctrace *create_trace(uint64_t trace_key, int spans_per_trace,
                                   int attrs_per_span, uint64_t seed)
{
    int i;
    int j;
    char name[64];
    char attr_key[32];
    char attr_val[32];
    uint8_t trace_id_buf[CTR_ID_OTEL_TRACE_SIZE];
    uint8_t span_id_buf[CTR_ID_OTEL_SPAN_SIZE];
    struct ctrace *ctr;
    struct ctrace_id *trace_id;
    struct ctrace_id *root_span_id = NULL;
    struct ctrace_id *span_id;
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span *scope_span;
    struct ctrace_span *span;

    ctr = ctr_create(NULL);
    if (!ctr) {
        return NULL;
    }

    resource_span = ctr_resource_span_create(ctr);
    if (!resource_span) {
        ctr_destroy(ctr);
        return NULL;
    }

    scope_span = ctr_scope_span_create(resource_span);
    if (!scope_span) {
        ctr_destroy(ctr);
        return NULL;
    }

    fill_id(trace_id_buf, sizeof(trace_id_buf), seed, trace_key, 0);
    trace_id = ctr_id_create((char *) trace_id_buf, sizeof(trace_id_buf));
    if (!trace_id) {
        ctr_destroy(ctr);
        return NULL;
    }

    for (i = 0; i < spans_per_trace; i++) {
        snprintf(name, sizeof(name), "span-%d", i);
        span = ctr_span_create(ctr, scope_span, name, NULL);
        if (!span) {
            ctr_id_destroy(trace_id);
            if (root_span_id) {
                ctr_id_destroy(root_span_id);
            }
            ctr_destroy(ctr);
            return NULL;
        }

        fill_id(span_id_buf, sizeof(span_id_buf), seed, trace_key, (uint64_t) i + 1);
        span_id = ctr_id_create((char *) span_id_buf, sizeof(span_id_buf));
        if (!span_id) {
            ctr_id_destroy(trace_id);
            if (root_span_id) {
                ctr_id_destroy(root_span_id);
            }
            ctr_destroy(ctr);
            return NULL;
        }

        ctr_span_set_trace_id_with_cid(span, trace_id);
        ctr_span_set_span_id_with_cid(span, span_id);

        if (i == 0) {
            root_span_id = ctr_id_create((char *) span_id_buf, sizeof(span_id_buf));
            if (!root_span_id) {
                ctr_id_destroy(span_id);
                ctr_id_destroy(trace_id);
                ctr_destroy(ctr);
                return NULL;
            }
        }
        else if (root_span_id) {
            ctr_span_set_parent_span_id_with_cid(span, root_span_id);
        }

        for (j = 0; j < attrs_per_span; j++) {
            snprintf(attr_key, sizeof(attr_key), "attr.%d", j);
            snprintf(attr_val, sizeof(attr_val), "value.%d", j);
            ctr_span_set_attribute_string(span, attr_key, attr_val);
        }

        ctr_id_destroy(span_id);
    }

    ctr_id_destroy(trace_id);
    if (root_span_id) {
        ctr_id_destroy(root_span_id);
    }

    return ctr;
}

static int run_probabilistic(int iterations, int spans_per_trace, int attrs_per_span,
                             int trace_cardinality, int sampling_percentage,
                             int warmup_iterations, uint64_t seed,
                             long *elapsed_ns, uint64_t *spans_processed)
{
    int i;
    int ret;
    struct timespec ts;
    struct timespec te;
    struct ctrace *ctr;
    struct ctrace *out_ctr;
    struct sampling ctx;
    struct flb_processor_instance ins;
    struct probabilistic_settings settings;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ins, 0, sizeof(ins));
    ctx.ins = &ins;

    settings.sampling_percentage = sampling_percentage;

    for (i = 0; i < warmup_iterations; i++) {
        ctr = create_trace((uint64_t) (i % trace_cardinality),
                           spans_per_trace, attrs_per_span, seed);
        if (!ctr) {
            return -1;
        }
        out_ctr = NULL;
        ret = sampling_probabilistic_plugin.cb_do_sampling(&ctx, &settings, ctr, &out_ctr);
        if (ret != 0) {
            ctr_destroy(ctr);
            return -1;
        }
        ctr_destroy(out_ctr);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (i = 0; i < iterations; i++) {
        ctr = create_trace((uint64_t) (i % trace_cardinality),
                           spans_per_trace, attrs_per_span, seed);
        if (!ctr) {
            return -1;
        }
        out_ctr = NULL;
        ret = sampling_probabilistic_plugin.cb_do_sampling(&ctx, &settings, ctr, &out_ctr);
        if (ret != 0) {
            ctr_destroy(ctr);
            return -1;
        }
        ctr_destroy(out_ctr);
    }
    clock_gettime(CLOCK_MONOTONIC, &te);

    *elapsed_ns = diff_ns(&ts, &te);
    *spans_processed = (uint64_t) iterations * (uint64_t) spans_per_trace;

    return 0;
}

static int run_tail_reconcile(int iterations, int spans_per_trace, int attrs_per_span,
                              int trace_cardinality, uint64_t max_traces,
                              int legacy_reconcile, int warmup_iterations, uint64_t seed,
                              long *elapsed_ns, uint64_t *spans_processed)
{
#ifndef FLB_SAMPLING_BENCH
    (void) iterations;
    (void) spans_per_trace;
    (void) attrs_per_span;
    (void) trace_cardinality;
    (void) max_traces;
    (void) legacy_reconcile;
    (void) warmup_iterations;
    (void) seed;
    (void) elapsed_ns;
    (void) spans_processed;
    return -1;
#else
    int i;
    int ret;
    struct timespec ts;
    struct timespec te;
    struct ctrace *ctr;
    struct sampling ctx;
    struct flb_processor_instance ins;
    struct sampling_span_registry *reg;
    uint64_t traces_out = 0;
    uint64_t spans_out = 0;
    uint64_t traces_now;
    uint64_t spans_now;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ins, 0, sizeof(ins));
    ctx.ins = &ins;

    reg = sampling_span_registry_create(max_traces);
    if (!reg) {
        return -1;
    }

    for (i = 0; i < warmup_iterations; i++) {
        ctr = create_trace((uint64_t) (i % trace_cardinality),
                           spans_per_trace, attrs_per_span, seed);
        if (!ctr) {
            sampling_span_registry_destroy(reg);
            return -1;
        }

        ret = sampling_span_registry_add_trace(&ctx, reg, ctr);
        if (ret != 0) {
            ctr_destroy(ctr);
            sampling_span_registry_destroy(reg);
            return -1;
        }

        ret = sampling_tail_bench_reconcile(&ctx, reg, legacy_reconcile, 0,
                                            &traces_now, &spans_now);
        ctr_destroy(ctr);
        if (ret != 0) {
            sampling_span_registry_destroy(reg);
            return -1;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    traces_out = 0;
    spans_out = 0;
    for (i = 0; i < iterations; i++) {
        ctr = create_trace((uint64_t) (i % trace_cardinality),
                           spans_per_trace, attrs_per_span, seed);
        if (!ctr) {
            sampling_span_registry_destroy(reg);
            return -1;
        }

        ret = sampling_span_registry_add_trace(&ctx, reg, ctr);
        if (ret != 0) {
            ctr_destroy(ctr);
            sampling_span_registry_destroy(reg);
            return -1;
        }

        ret = sampling_tail_bench_reconcile(&ctx, reg, legacy_reconcile, 0,
                                            &traces_now, &spans_now);
        ctr_destroy(ctr);
        if (ret != 0) {
            sampling_span_registry_destroy(reg);
            return -1;
        }
        traces_out += traces_now;
        spans_out += spans_now;
    }
    clock_gettime(CLOCK_MONOTONIC, &te);

    sampling_span_registry_destroy(reg);
    *elapsed_ns = diff_ns(&ts, &te);
    *spans_processed = spans_out;

    return 0;
#endif
}

int main(int argc, char **argv)
{
    int opt;
    int ret;
    int iterations = 10000;
    int warmup_iterations = 1000;
    int spans_per_trace = 20;
    int attrs_per_span = 4;
    int trace_cardinality = 2048;
    int sampling_percentage = 10;
    int legacy_reconcile = 0;
    uint64_t max_traces = 50000;
    uint64_t seed = 0x5eed1234ULL;
    long elapsed_ns;
    uint64_t spans_processed;
    double ns_per_span;
    double spans_per_sec;
    enum bench_mode mode = MODE_PROBABILISTIC;

    while ((opt = getopt(argc, argv, "m:i:w:s:a:c:p:L:t:S:h")) != -1) {
        switch (opt) {
        case 'm':
            if (strcmp(optarg, "probabilistic") == 0) {
                mode = MODE_PROBABILISTIC;
            }
            else if (strcmp(optarg, "tail-reconcile") == 0) {
                mode = MODE_TAIL_RECONCILE;
            }
            else {
                fprintf(stderr, "invalid mode: %s\n", optarg);
                return 1;
            }
            break;
        case 'i':
            iterations = atoi(optarg);
            break;
        case 'w':
            warmup_iterations = atoi(optarg);
            break;
        case 's':
            spans_per_trace = atoi(optarg);
            break;
        case 'a':
            attrs_per_span = atoi(optarg);
            break;
        case 'c':
            trace_cardinality = atoi(optarg);
            break;
        case 'p':
            sampling_percentage = atoi(optarg);
            break;
        case 'L':
            legacy_reconcile = atoi(optarg);
            break;
        case 't':
            max_traces = (uint64_t) strtoull(optarg, NULL, 10);
            break;
        case 'S':
            seed = (uint64_t) strtoull(optarg, NULL, 10);
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s [options]\n", argv[0]);
            fprintf(stderr, "  -m mode                probabilistic|tail-reconcile\n");
            fprintf(stderr, "  -i iterations          default: 10000\n");
            fprintf(stderr, "  -w warmup_iterations   default: 1000\n");
            fprintf(stderr, "  -s spans_per_trace     default: 20\n");
            fprintf(stderr, "  -a attrs_per_span      default: 4\n");
            fprintf(stderr, "  -c trace_cardinality   default: 2048\n");
            fprintf(stderr, "  -p sampling_percentage default: 10 (probabilistic)\n");
            fprintf(stderr, "  -L legacy_reconcile    0|1 (tail-reconcile)\n");
            fprintf(stderr, "  -t max_traces          default: 50000 (tail-reconcile)\n");
            fprintf(stderr, "  -S seed                default: 1592594996\n");
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (iterations <= 0 || warmup_iterations < 0 || spans_per_trace <= 0 ||
        attrs_per_span < 0 || trace_cardinality <= 0 || sampling_percentage < 0 ||
        sampling_percentage > 100 || (legacy_reconcile != 0 && legacy_reconcile != 1)) {
        fprintf(stderr, "invalid benchmark parameters\n");
        return 1;
    }

    if (mode == MODE_PROBABILISTIC) {
        ret = run_probabilistic(iterations, spans_per_trace, attrs_per_span,
                                trace_cardinality, sampling_percentage,
                                warmup_iterations, seed,
                                &elapsed_ns, &spans_processed);
    }
    else {
        ret = run_tail_reconcile(iterations, spans_per_trace, attrs_per_span,
                                 trace_cardinality, max_traces, legacy_reconcile,
                                 warmup_iterations, seed,
                                 &elapsed_ns, &spans_processed);
    }

    if (ret != 0) {
        fprintf(stderr, "benchmark failed\n");
        return 1;
    }

    ns_per_span = (double) elapsed_ns / (double) spans_processed;
    spans_per_sec = 1e9 / ns_per_span;

    printf("Processor sampling benchmark\n");
    printf("----------------------------\n");
    printf("Mode             : %s\n",
           mode == MODE_PROBABILISTIC ? "probabilistic" : "tail-reconcile");
    printf("Iterations       : %d\n", iterations);
    printf("Warmup iterations: %d\n", warmup_iterations);
    printf("Spans/trace      : %d\n", spans_per_trace);
    printf("Attrs/span       : %d\n", attrs_per_span);
    printf("Trace cardinality: %d\n", trace_cardinality);
    if (mode == MODE_PROBABILISTIC) {
        printf("Sampling %%        : %d\n", sampling_percentage);
    }
    else {
        printf("Legacy reconcile : %d\n", legacy_reconcile);
        printf("Max traces       : %" PRIu64 "\n", max_traces);
    }
    printf("----------------------------\n");
    printf("Total time       : %ld ns (%.3f s)\n", elapsed_ns, elapsed_ns / 1e9);
    printf("Total spans      : %" PRIu64 "\n", spans_processed);
    printf("Per span         : %.2f ns\n", ns_per_span);
    printf("Throughput       : %.0f spans/s\n", spans_per_sec);

    return 0;
}

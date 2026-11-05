/* Fluent Bit: bounded transactional log windows, Apache-2.0. */
#ifndef FLB_FTS_WINDOW_H
#define FLB_FTS_WINDOW_H

#include <stddef.h>
#include <stdint.h>

struct fts_window;
struct fts_runtime;

#define FTS_WINDOW_ACCEPT 0
#define FTS_WINDOW_LATE 1
#define FTS_WINDOW_OVERFLOW 2
#define FTS_WINDOW_ERROR -1
#define FTS_WINDOW_BUDGET -2

/* A successful emit consumes *buffer and clears it; failures preserve it. */
typedef int (*fts_window_emit_fn)(void *data, void **buffer, size_t bytes, size_t records,
                                  const char *tag, size_t tag_length);
typedef void (*fts_window_drop_fn)(void *data, size_t records, const char *reason);

struct fts_window *fts_window_create(size_t max_keys, size_t max_key_bytes,
                                      size_t limit, uint64_t hold_ms,
                                      uint64_t late_ms, uint64_t ready_ms);
void fts_window_clock(struct fts_window *window, uint64_t (*clock)(void *), void *data);
void fts_window_begin(struct fts_window *window);
int fts_window_classify(struct fts_window *window, const char *key, size_t length);
int fts_window_classify_work(struct fts_window *window, const char *key, size_t length, int *work);
/* Stage consumes *buffer only on ACCEPT. No state is committed per item. */
int fts_window_stage(struct fts_window *window, const char *key, size_t length,
                     void **buffer, size_t bytes, int error, int baseline_keep);
int fts_window_stage_tagged(struct fts_window *window, const char *key, size_t length,
                            void **buffer, size_t bytes, int error, int baseline_keep,
                            const char *tag, size_t tag_length);
void fts_window_count(struct fts_runtime *ctx, const char *outcome, size_t count);
size_t fts_window_pending(struct fts_window *window);
void fts_window_finish(struct fts_window *window, int commit);
void fts_window_poll(struct fts_window *window, fts_window_emit_fn emit,
                      fts_window_drop_fn drop, void *data);
void fts_window_stop(struct fts_window *window, fts_window_drop_fn drop, void *data);
void fts_window_destroy(struct fts_window *window);
size_t fts_window_bytes(struct fts_window *window);
size_t fts_window_records(struct fts_window *window);
size_t fts_window_poll_visits(struct fts_window *window);
int fts_window_register(struct fts_runtime *ctx);
int fts_window_runtime_start(struct fts_runtime *ctx);
void fts_window_runtime_stop(struct fts_runtime *ctx);
void fts_window_runtime_destroy(struct fts_runtime *ctx);
#endif

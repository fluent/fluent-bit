/* Fluent Bit: bounded transactional snapshot windows, Apache-2.0. */
#ifndef FLB_FTS_SNAPSHOT_WINDOW_H
#define FLB_FTS_SNAPSHOT_WINDOW_H
#include <stddef.h>
#include <stdint.h>
struct cfl_variant;
struct fts_snapshot_window;
#define FTS_SNAPSHOT_ACCEPT 0
#define FTS_SNAPSHOT_OVERFLOW 1
#define FTS_SNAPSHOT_ERROR -1
#define FTS_SNAPSHOT_BUDGET -2
/* Payload remains owned by the window. Emit must copy/adopt an independent
 * representation before success; BUSY/errors preserve the frozen snapshot. */
typedef int (*fts_snapshot_emit_fn)(void *, const void *, size_t, size_t,
                                     const char *, size_t);
typedef void (*fts_snapshot_settle_fn)(void *, size_t, const char *);
struct fts_snapshot_window *fts_snapshot_window_create(size_t, size_t, size_t,
                                                       size_t, uint64_t, uint64_t);
void fts_snapshot_window_clock(struct fts_snapshot_window *, uint64_t (*)(void *), void *);
void fts_snapshot_window_begin(struct fts_snapshot_window *);
const struct cfl_variant *fts_snapshot_window_get(struct fts_snapshot_window *,
                                                  const char *, size_t, size_t *, int *);
int fts_snapshot_window_put(struct fts_snapshot_window *, const char *, size_t,
                             const struct cfl_variant *, void **, size_t,
                             const char *, size_t, int *);
/* At most one proposal per input callback. KEEP/DROP/error abort that proposal;
 * HOLD accepts it into the batch overlay. Final construction commits the batch. */
int fts_snapshot_window_item(struct fts_snapshot_window *, int);
void fts_snapshot_window_finish(struct fts_snapshot_window *, int);
void fts_snapshot_window_poll(struct fts_snapshot_window *, fts_snapshot_emit_fn,
                               fts_snapshot_settle_fn, void *);
void fts_snapshot_window_stop(struct fts_snapshot_window *, fts_snapshot_settle_fn, void *);
void fts_snapshot_window_destroy(struct fts_snapshot_window *);
size_t fts_snapshot_window_pending(struct fts_snapshot_window *);
size_t fts_snapshot_window_held(struct fts_snapshot_window *);
size_t fts_snapshot_window_bytes(struct fts_snapshot_window *);
#endif

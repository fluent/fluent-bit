/* Fluent Bit: metric adapter for generic snapshot windows, Apache-2.0. */
#ifndef FLB_FTS_METRIC_WINDOW_H
#define FLB_FTS_METRIC_WINDOW_H
#include "fts.h"
int fts_metric_window_register(struct fts_runtime *);
int fts_metric_window_start(struct fts_runtime *);
void fts_metric_window_stop(struct fts_runtime *);
void fts_metric_window_destroy(struct fts_runtime *);
void fts_metric_window_begin(struct fts_runtime *);
int fts_metric_window_requested(struct fts_runtime *);
int fts_metric_window_propose(struct fts_runtime *);
void fts_metric_window_item_end(struct fts_runtime *, int);
void fts_metric_window_finish(struct fts_runtime *, int);
#endif

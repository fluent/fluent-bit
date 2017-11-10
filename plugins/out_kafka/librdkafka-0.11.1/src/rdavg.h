#pragma once


typedef struct rd_avg_s {
        struct {
                int64_t maxv;
                int64_t minv;
                int64_t avg;
                int64_t sum;
                int     cnt;
                rd_ts_t start;
        } ra_v;
        mtx_t ra_lock;
        enum {
                RD_AVG_GAUGE,
                RD_AVG_COUNTER,
        } ra_type;
} rd_avg_t;


/**
 * Add timestamp 'ts' to averager 'ra'.
 */
static RD_UNUSED void rd_avg_add (rd_avg_t *ra, int64_t v) {
        mtx_lock(&ra->ra_lock);
	if (v > ra->ra_v.maxv)
		ra->ra_v.maxv = v;
	if (ra->ra_v.minv == 0 || v < ra->ra_v.minv)
		ra->ra_v.minv = v;
	ra->ra_v.sum += v;
	ra->ra_v.cnt++;
        mtx_unlock(&ra->ra_lock);
}


/**
 * @brief Calculate the average
 */
static RD_UNUSED void rd_avg_calc (rd_avg_t *ra, rd_ts_t now) {
        if (ra->ra_type == RD_AVG_GAUGE) {
                if (ra->ra_v.cnt)
                        ra->ra_v.avg = ra->ra_v.sum / ra->ra_v.cnt;
                else
                        ra->ra_v.avg = 0;
        } else {
                rd_ts_t elapsed = now - ra->ra_v.start;

                if (elapsed)
                        ra->ra_v.avg = (ra->ra_v.sum * 1000000llu) / elapsed;
                else
                        ra->ra_v.avg = 0;

                ra->ra_v.start = elapsed;
        }
}


/**
 * Rolls over statistics in 'src' and stores the average in 'dst'.
 * 'src' is cleared and ready to be reused.
 */
static RD_UNUSED void rd_avg_rollover (rd_avg_t *dst,
					     rd_avg_t *src) {
        rd_ts_t now = rd_clock();

        mtx_lock(&src->ra_lock);
        dst->ra_type = src->ra_type;
	dst->ra_v    = src->ra_v;
	memset(&src->ra_v, 0, sizeof(src->ra_v));
        src->ra_v.start = now;
        mtx_unlock(&src->ra_lock);

        rd_avg_calc(dst, now);
}


/**
 * Initialize an averager
 */
static RD_UNUSED void rd_avg_init (rd_avg_t *ra, int type) {
        rd_avg_t dummy;
        memset(ra, 0, sizeof(*ra));
        mtx_init(&ra->ra_lock, 0);
        ra->ra_type = type;

        rd_avg_rollover(&dummy, ra);
}

/**
 * Destroy averager
 */
static RD_UNUSED void rd_avg_destroy (rd_avg_t *ra) {
        mtx_destroy(&ra->ra_lock);
}


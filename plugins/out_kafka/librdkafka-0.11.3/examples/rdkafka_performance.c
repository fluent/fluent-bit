/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012, Magnus Edenhill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Apache Kafka consumer & producer performance tester
 * using the Kafka driver from librdkafka
 * (https://github.com/edenhill/librdkafka)
 */

#ifdef _MSC_VER
#define  _CRT_SECURE_NO_WARNINGS /* Silence nonsense on MSVC */
#endif

#include "../src/rd.h"

#define _GNU_SOURCE /* for strndup() */
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */
/* Do not include these defines from your program, they will not be
 * provided by librdkafka. */
#include "rd.h"
#include "rdtime.h"

#ifdef _MSC_VER
#include "../win32/wingetopt.h"
#include "../win32/wintime.h"
#endif


static int run = 1;
static int forever = 1;
static rd_ts_t dispintvl = 1000;
static int do_seq = 0;
static int exit_after = 0;
static int exit_eof = 0;
static FILE *stats_fp;
static int dr_disp_div;
static int verbosity = 1;
static int latency_mode = 0;
static int report_offset = 0;
static FILE *latency_fp = NULL;
static int msgcnt = -1;
static int incremental_mode = 0;
static int partition_cnt = 0;
static int eof_cnt = 0;
static int with_dr = 1;

static void stop (int sig) {
        if (!run)
                exit(0);
	run = 0;
}

static long int msgs_wait_cnt = 0;
static long int msgs_wait_produce_cnt = 0;
static rd_ts_t t_end;
static rd_kafka_t *global_rk;

struct avg {
        int64_t  val;
        int      cnt;
        uint64_t ts_start;
};

static struct {
	rd_ts_t  t_start;
	rd_ts_t  t_end;
	rd_ts_t  t_end_send;
	uint64_t msgs;
	uint64_t msgs_last;
        uint64_t msgs_dr_ok;
        uint64_t msgs_dr_err;
        uint64_t bytes_dr_ok;
	uint64_t bytes;
	uint64_t bytes_last;
	uint64_t tx;
	uint64_t tx_err;
        uint64_t avg_rtt;
        uint64_t offset;
	rd_ts_t  t_fetch_latency;
	rd_ts_t  t_last;
        rd_ts_t  t_enobufs_last;
	rd_ts_t  t_total;
        rd_ts_t  latency_last;
        rd_ts_t  latency_lo;
        rd_ts_t  latency_hi;
        rd_ts_t  latency_sum;
        int      latency_cnt;
        int64_t  last_offset;
} cnt;


uint64_t wall_clock (void) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return ((uint64_t)tv.tv_sec * 1000000LLU) +
		((uint64_t)tv.tv_usec);
}

static void err_cb (rd_kafka_t *rk, int err, const char *reason, void *opaque) {
	printf("%% ERROR CALLBACK: %s: %s: %s\n",
	       rd_kafka_name(rk), rd_kafka_err2str(err), reason);
}

static void throttle_cb (rd_kafka_t *rk, const char *broker_name,
			 int32_t broker_id, int throttle_time_ms,
			 void *opaque) {
	printf("%% THROTTLED %dms by %s (%"PRId32")\n", throttle_time_ms,
	       broker_name, broker_id);
}

static void offset_commit_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                              rd_kafka_topic_partition_list_t *offsets,
                              void *opaque) {
        int i;

        if (err || verbosity >= 2)
                printf("%% Offset commit of %d partition(s): %s\n",
                       offsets->cnt, rd_kafka_err2str(err));

        for (i = 0 ; i < offsets->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar = &offsets->elems[i];
                if (rktpar->err || verbosity >= 2)
                        printf("%%  %s [%"PRId32"] @ %"PRId64": %s\n",
                               rktpar->topic, rktpar->partition,
                               rktpar->offset, rd_kafka_err2str(err));
        }
}

/**
 * @brief Add latency measurement
 */
static void latency_add (int64_t ts, const char *who) {
        if (ts > cnt.latency_hi)
                cnt.latency_hi = ts;
        if (!cnt.latency_lo || ts < cnt.latency_lo)
                cnt.latency_lo = ts;
        cnt.latency_last = ts;
        cnt.latency_cnt++;
        cnt.latency_sum += ts;
        if (latency_fp)
                fprintf(latency_fp, "%"PRIu64"\n", ts);
}


static void msg_delivered (rd_kafka_t *rk,
                           const rd_kafka_message_t *rkmessage, void *opaque) {
	static rd_ts_t last;
	rd_ts_t now = rd_clock();
	static int msgs;

	msgs++;

	msgs_wait_cnt--;

	if (rkmessage->err)
                cnt.msgs_dr_err++;
        else {
                cnt.msgs_dr_ok++;
                cnt.bytes_dr_ok += rkmessage->len;
        }

        if (latency_mode) {
                /* Extract latency */
                int64_t source_ts;
                if (sscanf(rkmessage->payload, "LATENCY:%"SCNd64,
                           &source_ts) == 1)
                        latency_add(wall_clock() - source_ts, "producer");
        }


	if ((rkmessage->err &&
	     (cnt.msgs_dr_err < 50 ||
              !(cnt.msgs_dr_err % (dispintvl / 1000)))) ||
	    !last || msgs_wait_cnt < 5 ||
	    !(msgs_wait_cnt % dr_disp_div) || 
	    (now - last) >= dispintvl * 1000 ||
            verbosity >= 3) {
		if (rkmessage->err && verbosity >= 2)
			printf("%% Message delivery failed: %s [%"PRId32"]: "
			       "%s (%li remain)\n",
			       rd_kafka_topic_name(rkmessage->rkt),
			       rkmessage->partition,
			       rd_kafka_err2str(rkmessage->err),
			       msgs_wait_cnt);
		else if (verbosity > 2)
			printf("%% Message delivered (offset %"PRId64"): "
                               "%li remain\n",
                               rkmessage->offset, msgs_wait_cnt);
		if (verbosity >= 3 && do_seq)
			printf(" --> \"%.*s\"\n",
                               (int)rkmessage->len,
                               (const char *)rkmessage->payload);
		last = now;
	}

        if (report_offset)
                cnt.last_offset = rkmessage->offset;

	if (msgs_wait_produce_cnt == 0 && msgs_wait_cnt == 0 && !forever) {
		if (verbosity >= 2)
			printf("All messages delivered!\n");
		t_end = rd_clock();
		run = 0;
	}

	if (exit_after && exit_after <= msgs) {
		printf("%% Hard exit after %i messages, as requested\n",
		       exit_after);
		exit(0);
	}
}


static void msg_consume (rd_kafka_message_t *rkmessage, void *opaque) {

	if (rkmessage->err) {
		if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                        cnt.offset = rkmessage->offset;

                        if (verbosity >= 1)
                                printf("%% Consumer reached end of "
                                       "%s [%"PRId32"] "
                                       "message queue at offset %"PRId64"\n",
                                       rd_kafka_topic_name(rkmessage->rkt),
                                       rkmessage->partition, rkmessage->offset);

			if (exit_eof && ++eof_cnt == partition_cnt)
				run = 0;

			return;
		}

		printf("%% Consume error for topic \"%s\" [%"PRId32"] "
		       "offset %"PRId64": %s\n",
		       rkmessage->rkt ? rd_kafka_topic_name(rkmessage->rkt):"",
		       rkmessage->partition,
		       rkmessage->offset,
		       rd_kafka_message_errstr(rkmessage));

                if (rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION ||
                    rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
                        run = 0;

                cnt.msgs_dr_err++;
		return;
	}

	/* Start measuring from first message received */
	if (!cnt.t_start)
		cnt.t_start = cnt.t_last = rd_clock();

        cnt.offset = rkmessage->offset;
	cnt.msgs++;
	cnt.bytes += rkmessage->len;

	if (verbosity >= 3 ||
            (verbosity >= 2 && !(cnt.msgs % 1000000)))
		printf("@%"PRId64": %.*s: %.*s\n",
		       rkmessage->offset,
                       (int)rkmessage->key_len, (char *)rkmessage->key,
		       (int)rkmessage->len, (char *)rkmessage->payload);


        if (latency_mode) {
                int64_t remote_ts, ts;

                if (rkmessage->len > 8 &&
                    !memcmp(rkmessage->payload, "LATENCY:", 8) &&
                    sscanf(rkmessage->payload, "LATENCY:%"SCNd64,
                           &remote_ts) == 1) {
                        ts = wall_clock() - remote_ts;
                        if (ts > 0 && ts < (1000000 * 60 * 5)) {
                                latency_add(ts, "consumer");
                        } else {
                                if (verbosity >= 1)
                                        printf("Received latency timestamp is too far off: %"PRId64"us (message offset %"PRId64"): ignored\n",
                                               ts, rkmessage->offset);
                        }
                } else if (verbosity > 1)
                        printf("not a LATENCY payload: %.*s\n",
                               (int)rkmessage->len,
                               (char *)rkmessage->payload);

        }

        if (msgcnt != -1 && (int)cnt.msgs >= msgcnt)
                run = 0;
}


static void rebalance_cb (rd_kafka_t *rk,
			  rd_kafka_resp_err_t err,
			  rd_kafka_topic_partition_list_t *partitions,
			  void *opaque) {

	switch (err)
	{
	case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
		fprintf(stderr,
			"%% Group rebalanced: %d partition(s) assigned\n",
			partitions->cnt);
		eof_cnt = 0;
		partition_cnt = partitions->cnt;
		rd_kafka_assign(rk, partitions);
		break;

	case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
		fprintf(stderr,
			"%% Group rebalanced: %d partition(s) revoked\n",
			partitions->cnt);
		eof_cnt = 0;
		partition_cnt = 0;
		rd_kafka_assign(rk, NULL);
		break;

	default:
		break;
	}
}


/**
 * Find and extract single value from a two-level search.
 * First find 'field1', then find 'field2' and extract its value.
 * Returns 0 on miss else the value.
 */
static uint64_t json_parse_fields (const char *json, const char **end,
                                   const char *field1, const char *field2) {
        const char *t = json;
        const char *t2;
        int len1 = (int)strlen(field1);
        int len2 = (int)strlen(field2);

        while ((t2 = strstr(t, field1))) {
                uint64_t v;

                t = t2;
                t += len1;

                /* Find field */
                if (!(t2 = strstr(t, field2)))
                        continue;
                t2 += len2;

                while (isspace((int)*t2))
                        t2++;

                v = strtoull(t2, (char **)&t, 10);
                if (t2 == t)
                        continue;

                *end = t;
                return v;
        }

        *end = t + strlen(t);
        return 0;
}

/**
 * Parse various values from rdkafka stats
 */
static void json_parse_stats (const char *json) {
        const char *t;
#define MAX_AVGS 100 /* max number of brokers to scan for rtt */
        uint64_t avg_rtt[MAX_AVGS+1];
        int avg_rtt_i     = 0;

        /* Store totals at end of array */
        avg_rtt[MAX_AVGS]     = 0;

        /* Extract all broker RTTs */
        t = json;
        while (avg_rtt_i < MAX_AVGS && *t) {
                avg_rtt[avg_rtt_i] = json_parse_fields(t, &t,
                                                       "\"rtt\":",
                                                       "\"avg\":");

                /* Skip low RTT values, means no messages are passing */
                if (avg_rtt[avg_rtt_i] < 100 /*0.1ms*/)
                        continue;


                avg_rtt[MAX_AVGS] += avg_rtt[avg_rtt_i];
                avg_rtt_i++;
        }

        if (avg_rtt_i > 0)
                avg_rtt[MAX_AVGS] /= avg_rtt_i;

        cnt.avg_rtt = avg_rtt[MAX_AVGS];
}


static int stats_cb (rd_kafka_t *rk, char *json, size_t json_len,
		     void *opaque) {

        /* Extract values for our own stats */
        json_parse_stats(json);

        if (stats_fp)
                fprintf(stats_fp, "%s\n", json);
	return 0;
}

#define _OTYPE_TAB      0x1  /* tabular format */
#define _OTYPE_SUMMARY  0x2  /* summary format */
#define _OTYPE_FORCE    0x4  /* force output regardless of interval timing */
static void print_stats (rd_kafka_t *rk,
                         int mode, int otype, const char *compression) {
	rd_ts_t now = rd_clock();
	rd_ts_t t_total;
        static int rows_written = 0;
        int print_header;
        double latency_avg = 0.0f;
        char extra[512];
        int extra_of = 0;
        *extra = '\0';

	if (!(otype & _OTYPE_FORCE) &&
            (((otype & _OTYPE_SUMMARY) && verbosity == 0) ||
             cnt.t_last + dispintvl > now))
		return;

        print_header = !rows_written ||(verbosity > 0 && !(rows_written % 20));

	if (cnt.t_end_send)
		t_total = cnt.t_end_send - cnt.t_start;
	else if (cnt.t_end)
		t_total = cnt.t_end - cnt.t_start;
	else if (cnt.t_start)
		t_total = now - cnt.t_start;
	else
		t_total = 1;

        if (latency_mode && cnt.latency_cnt)
                latency_avg = (double)cnt.latency_sum /
                        (double)cnt.latency_cnt;

        if (mode == 'P') {

                if (otype & _OTYPE_TAB) {
#define ROW_START()        do {} while (0)
#define COL_HDR(NAME)      printf("| %10.10s ", (NAME))
#define COL_PR64(NAME,VAL) printf("| %10"PRIu64" ", (VAL))
#define COL_PRF(NAME,VAL)  printf("| %10.2f ", (VAL))
#define ROW_END()          do {                 \
                                printf("\n");   \
                                rows_written++; \
                        } while (0)

                        if (print_header) {
                                /* First time, print header */
                                ROW_START();
                                COL_HDR("elapsed");
                                COL_HDR("msgs");
                                COL_HDR("bytes");
                                COL_HDR("rtt");
                                COL_HDR("dr");
                                COL_HDR("dr_m/s");
                                COL_HDR("dr_MB/s");
                                COL_HDR("dr_err");
                                COL_HDR("tx_err");
                                COL_HDR("outq");
                                if (report_offset)
                                        COL_HDR("offset");
                                if (latency_mode) {
                                        COL_HDR("lat_curr");
                                        COL_HDR("lat_avg");
                                        COL_HDR("lat_lo");
                                        COL_HDR("lat_hi");
                                }

                                ROW_END();
                        }

                        ROW_START();
                        COL_PR64("elapsed", t_total / 1000);
                        COL_PR64("msgs", cnt.msgs);
                        COL_PR64("bytes", cnt.bytes);
                        COL_PR64("rtt", cnt.avg_rtt / 1000);
                        COL_PR64("dr", cnt.msgs_dr_ok);
                        COL_PR64("dr_m/s",
                                 ((cnt.msgs_dr_ok * 1000000) / t_total));
                        COL_PRF("dr_MB/s",
                                (float)((cnt.bytes_dr_ok) / (float)t_total));
                        COL_PR64("dr_err", cnt.msgs_dr_err);
                        COL_PR64("tx_err", cnt.tx_err);
                        COL_PR64("outq",
                                 rk ? (uint64_t)rd_kafka_outq_len(rk) : 0);
                        if (report_offset)
                                COL_PR64("offset", (uint64_t)cnt.last_offset);
                        if (latency_mode) {
                                COL_PRF("lat_curr", cnt.latency_last / 1000.0f);
                                COL_PRF("lat_avg", latency_avg / 1000.0f);
                                COL_PRF("lat_lo", cnt.latency_lo / 1000.0f);
                                COL_PRF("lat_hi", cnt.latency_hi / 1000.0f);
                        }
                        ROW_END();
                }

                if (otype & _OTYPE_SUMMARY) {
                        printf("%% %"PRIu64" messages produced "
                               "(%"PRIu64" bytes), "
                               "%"PRIu64" delivered "
                               "(offset %"PRId64", %"PRIu64" failed) "
                               "in %"PRIu64"ms: %"PRIu64" msgs/s and "
                               "%.02f MB/s, "
                               "%"PRIu64" produce failures, %i in queue, "
                               "%s compression\n",
                               cnt.msgs, cnt.bytes,
                               cnt.msgs_dr_ok, cnt.last_offset, cnt.msgs_dr_err,
                               t_total / 1000,
                               ((cnt.msgs_dr_ok * 1000000) / t_total),
                               (float)((cnt.bytes_dr_ok) / (float)t_total),
                               cnt.tx_err,
                               rk ? rd_kafka_outq_len(rk) : 0,
                               compression);
                }

        } else {

                if (otype & _OTYPE_TAB) {
                        if (print_header) {
                                /* First time, print header */
                                ROW_START();
                                COL_HDR("elapsed");
                                COL_HDR("msgs");
                                COL_HDR("bytes");
                                COL_HDR("rtt");
                                COL_HDR("m/s");
                                COL_HDR("MB/s");
                                COL_HDR("rx_err");
                                COL_HDR("offset");
                                if (latency_mode) {
                                        COL_HDR("lat_curr");
                                        COL_HDR("lat_avg");
                                        COL_HDR("lat_lo");
                                        COL_HDR("lat_hi");
                                }
                                ROW_END();
                        }

                        ROW_START();
                        COL_PR64("elapsed", t_total / 1000);
                        COL_PR64("msgs", cnt.msgs);
                        COL_PR64("bytes", cnt.bytes);
                        COL_PR64("rtt", cnt.avg_rtt / 1000);
                        COL_PR64("m/s",
                                 ((cnt.msgs * 1000000) / t_total));
                        COL_PRF("MB/s",
                                (float)((cnt.bytes) / (float)t_total));
                        COL_PR64("rx_err", cnt.msgs_dr_err);
                        COL_PR64("offset", cnt.offset);
                        if (latency_mode) {
                                COL_PRF("lat_curr", cnt.latency_last / 1000.0f);
                                COL_PRF("lat_avg", latency_avg / 1000.0f);
                                COL_PRF("lat_lo", cnt.latency_lo / 1000.0f);
                                COL_PRF("lat_hi", cnt.latency_hi / 1000.0f);
                        }
                        ROW_END();

                }

                if (otype & _OTYPE_SUMMARY) {
                        if (latency_avg >= 1.0f)
                                extra_of += rd_snprintf(extra+extra_of,
                                                     sizeof(extra)-extra_of,
                                                     ", latency "
                                                     "curr/avg/lo/hi "
                                                     "%.2f/%.2f/%.2f/%.2fms",
                                                     cnt.latency_last / 1000.0f,
                                                     latency_avg  / 1000.0f,
                                                     cnt.latency_lo / 1000.0f,
                                                     cnt.latency_hi / 1000.0f)
;
                        printf("%% %"PRIu64" messages (%"PRIu64" bytes) "
                               "consumed in %"PRIu64"ms: %"PRIu64" msgs/s "
                               "(%.02f MB/s)"
                               "%s\n",
                               cnt.msgs, cnt.bytes,
                               t_total / 1000,
                               ((cnt.msgs * 1000000) / t_total),
                               (float)((cnt.bytes) / (float)t_total),
                               extra);
                }

                if (incremental_mode && now > cnt.t_last) {
                        uint64_t i_msgs = cnt.msgs - cnt.msgs_last;
                        uint64_t i_bytes = cnt.bytes - cnt.bytes_last;
                        uint64_t i_time = cnt.t_last ? now - cnt.t_last : 0;

                        printf("%% INTERVAL: %"PRIu64" messages "
                               "(%"PRIu64" bytes) "
                               "consumed in %"PRIu64"ms: %"PRIu64" msgs/s "
                               "(%.02f MB/s)"
                               "%s\n",
                               i_msgs, i_bytes,
                               i_time / 1000,
                               ((i_msgs * 1000000) / i_time),
                               (float)((i_bytes) / (float)i_time),
                               extra);

                }
        }

	cnt.t_last = now;
	cnt.msgs_last = cnt.msgs;
	cnt.bytes_last = cnt.bytes;
}


static void sig_usr1 (int sig) {
	rd_kafka_dump(stdout, global_rk);
}


/**
 * @brief Read config from file
 * @returns -1 on error, else 0.
 */
static int read_conf_file (rd_kafka_conf_t *conf,
                           rd_kafka_topic_conf_t *tconf, const char *path) {
        FILE *fp;
        char buf[512];
        int line = 0;
        char errstr[512];

        if (!(fp = fopen(path, "r"))) {
                fprintf(stderr, "%% Failed to open %s: %s\n",
                        path, strerror(errno));
                return -1;
        }

        while (fgets(buf, sizeof(buf), fp)) {
                char *s = buf;
                char *t;
                rd_kafka_conf_res_t r = RD_KAFKA_CONF_UNKNOWN;

                line++;

                while (isspace((int)*s))
                        s++;

                if (!*s || *s == '#')
                        continue;

                if ((t = strchr(buf, '\n')))
                        *t = '\0';

                t = strchr(buf, '=');
                if (!t || t == s || !*(t+1)) {
                        fprintf(stderr, "%% %s:%d: expected key=value\n",
                                path, line);
                        fclose(fp);
                        return -1;
                }

                *(t++) = '\0';

                /* Try property on topic config first */
                if (tconf)
                        r = rd_kafka_topic_conf_set(tconf, s, t,
                                                    errstr, sizeof(errstr));

                /* Try global config */
                if (r == RD_KAFKA_CONF_UNKNOWN)
                        r = rd_kafka_conf_set(conf, s, t,
                                              errstr, sizeof(errstr));

                if (r == RD_KAFKA_CONF_OK)
                        continue;

                fprintf(stderr, "%% %s:%d: %s=%s: %s\n",
                        path, line, s, t, errstr);
                fclose(fp);
                return -1;
        }

        fclose(fp);

        return 0;
}



int main (int argc, char **argv) {
	char *brokers = NULL;
	char mode = 'C';
	char *topic = NULL;
	const char *key = NULL;
        int *partitions = NULL;
	int opt;
	int sendflags = 0;
	char *msgpattern = "librdkafka_performance testing!";
	int msgsize = (int)strlen(msgpattern);
	const char *debug = NULL;
	rd_ts_t now;
	char errstr[512];
	uint64_t seq = 0;
	int seed = (int)time(NULL);
        rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	rd_kafka_queue_t *rkqu = NULL;
	const char *compression = "no";
	int64_t start_offset = 0;
	int batch_size = 0;
	int idle = 0;
        const char *stats_cmd = NULL;
        char *stats_intvlstr = NULL;
        char tmp[128];
        char *tmp2;
        int otype = _OTYPE_SUMMARY;
        double dtmp;
        int rate_sleep = 0;
	rd_kafka_topic_partition_list_t *topics;
        int exitcode = 0;

	/* Kafka configuration */
	conf = rd_kafka_conf_new();
	rd_kafka_conf_set_error_cb(conf, err_cb);
	rd_kafka_conf_set_throttle_cb(conf, throttle_cb);
        rd_kafka_conf_set_offset_commit_cb(conf, offset_commit_cb);

#ifdef SIGIO
        /* Quick termination */
	rd_snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);
#endif

	/* Producer config */
	rd_kafka_conf_set(conf, "queue.buffering.max.messages", "500000",
			  NULL, 0);
	rd_kafka_conf_set(conf, "message.send.max.retries", "3", NULL, 0);
	rd_kafka_conf_set(conf, "retry.backoff.ms", "500", NULL, 0);

	/* Consumer config */
	/* Tell rdkafka to (try to) maintain 1M messages
	 * in its internal receive buffers. This is to avoid
	 * application -> rdkafka -> broker  per-message ping-pong
	 * latency.
	 * The larger the local queue, the higher the performance.
	 * Try other values with: ... -X queued.min.messages=1000
	 */
	rd_kafka_conf_set(conf, "queued.min.messages", "1000000", NULL, 0);
	rd_kafka_conf_set(conf, "session.timeout.ms", "6000", NULL, 0);

	/* Kafka topic configuration */
	topic_conf = rd_kafka_topic_conf_new();
	rd_kafka_topic_conf_set(topic_conf, "auto.offset.reset", "earliest",
				NULL, 0);

	topics = rd_kafka_topic_partition_list_new(1);

	while ((opt =
		getopt(argc, argv,
		       "PCG:t:p:b:s:k:c:fi:MDd:m:S:x:"
                       "R:a:z:o:X:B:eT:Y:qvIur:lA:OwN")) != -1) {
		switch (opt) {
		case 'G':
			if (rd_kafka_conf_set(conf, "group.id", optarg,
					      errstr, sizeof(errstr)) !=
			    RD_KAFKA_CONF_OK) {
				fprintf(stderr, "%% %s\n", errstr);
				exit(1);
			}
			/* FALLTHRU */
		case 'P':
		case 'C':
			mode = opt;
			break;
		case 't':
			rd_kafka_topic_partition_list_add(topics, optarg,
							  RD_KAFKA_PARTITION_UA);
			break;
		case 'p':
                        partition_cnt++;
			partitions = realloc(partitions, sizeof(*partitions) * partition_cnt);
			partitions[partition_cnt-1] = atoi(optarg);
			break;

		case 'b':
			brokers = optarg;
			break;
		case 's':
			msgsize = atoi(optarg);
			break;
		case 'k':
			key = optarg;
			break;
		case 'c':
			msgcnt = atoi(optarg);
			break;
		case 'D':
			sendflags |= RD_KAFKA_MSG_F_FREE;
			break;
		case 'i':
			dispintvl = atoi(optarg);
			break;
		case 'm':
			msgpattern = optarg;
			break;
		case 'S':
			seq = strtoull(optarg, NULL, 10);
			do_seq = 1;
			break;
		case 'x':
			exit_after = atoi(optarg);
			break;
		case 'R':
			seed = atoi(optarg);
			break;
		case 'a':
			if (rd_kafka_topic_conf_set(topic_conf,
						    "request.required.acks",
						    optarg,
						    errstr, sizeof(errstr)) !=
			    RD_KAFKA_CONF_OK) {
				fprintf(stderr, "%% %s\n", errstr);
				exit(1);
			}
			break;
		case 'B':
			batch_size = atoi(optarg);
			break;
		case 'z':
			if (rd_kafka_conf_set(conf, "compression.codec",
					      optarg,
					      errstr, sizeof(errstr)) !=
			    RD_KAFKA_CONF_OK) {
				fprintf(stderr, "%% %s\n", errstr);
				exit(1);
			}
			compression = optarg;
			break;
		case 'o':
			if (!strcmp(optarg, "end"))
				start_offset = RD_KAFKA_OFFSET_END;
			else if (!strcmp(optarg, "beginning"))
				start_offset = RD_KAFKA_OFFSET_BEGINNING;
			else if (!strcmp(optarg, "stored"))
				start_offset = RD_KAFKA_OFFSET_STORED;
			else {
				start_offset = strtoll(optarg, NULL, 10);

				if (start_offset < 0)
					start_offset = RD_KAFKA_OFFSET_TAIL(-start_offset);
			}

			break;
		case 'e':
			exit_eof = 1;
			break;
		case 'd':
			debug = optarg;
			break;
		case 'X':
		{
			char *name, *val;
			rd_kafka_conf_res_t res;

			if (!strcmp(optarg, "list") ||
			    !strcmp(optarg, "help")) {
				rd_kafka_conf_properties_show(stdout);
				exit(0);
			}

			name = optarg;
			if (!(val = strchr(name, '='))) {
				fprintf(stderr, "%% Expected "
					"-X property=value, not %s\n", name);
				exit(1);
			}

			*val = '\0';
			val++;

                        if (!strcmp(name, "file")) {
                                if (read_conf_file(conf, topic_conf, val) == -1)
                                        exit(1);
                                break;
                        }

			res = RD_KAFKA_CONF_UNKNOWN;
			/* Try "topic." prefixed properties on topic
			 * conf first, and then fall through to global if
			 * it didnt match a topic configuration property. */
			if (!strncmp(name, "topic.", strlen("topic.")))
				res = rd_kafka_topic_conf_set(topic_conf,
							      name+
							      strlen("topic."),
							      val,
							      errstr,
							      sizeof(errstr));

			if (res == RD_KAFKA_CONF_UNKNOWN)
				res = rd_kafka_conf_set(conf, name, val,
							errstr, sizeof(errstr));

			if (res != RD_KAFKA_CONF_OK) {
				fprintf(stderr, "%% %s\n", errstr);
				exit(1);
			}
		}
		break;

		case 'T':
                        stats_intvlstr = optarg;
			break;
                case 'Y':
                        stats_cmd = optarg;
                        break;

		case 'q':
                        verbosity--;
			break;

		case 'v':
                        verbosity++;
			break;

		case 'I':
			idle = 1;
			break;

                case 'u':
                        otype = _OTYPE_TAB;
                        verbosity--; /* remove some fluff */
                        break;

                case 'r':
                        dtmp = strtod(optarg, &tmp2);
                        if (tmp2 == optarg ||
                            (dtmp >= -0.001 && dtmp <= 0.001)) {
                                fprintf(stderr, "%% Invalid rate: %s\n",
                                        optarg);
                                exit(1);
                        }

                        rate_sleep = (int)(1000000.0 / dtmp);
                        break;

                case 'l':
                        latency_mode = 1;
			break;

		case 'A':
			if (!(latency_fp = fopen(optarg, "w"))) {
				fprintf(stderr,
					"%% Cant open %s: %s\n",
					optarg, strerror(errno));
				exit(1);
			}
                        break;

                case 'O':
                        if (rd_kafka_topic_conf_set(topic_conf,
                                                    "produce.offset.report",
                                                    "true",
                                                    errstr, sizeof(errstr)) !=
                            RD_KAFKA_CONF_OK) {
                                fprintf(stderr, "%% %s\n", errstr);
                                exit(1);
                        }
                        report_offset = 1;
                        break;

		case 'M':
			incremental_mode = 1;
			break;

		case 'N':
			with_dr = 0;
			break;

		default:
                        fprintf(stderr, "Unknown option: %c\n", opt);
			goto usage;
		}
	}

	if (topics->cnt == 0 || optind != argc) {
                if (optind < argc)
                        fprintf(stderr, "Unknown argument: %s\n", argv[optind]);
	usage:
		fprintf(stderr,
			"Usage: %s [-C|-P] -t <topic> "
			"[-p <partition>] [-b <broker,broker..>] [options..]\n"
			"\n"
			"librdkafka version %s (0x%08x)\n"
			"\n"
			" Options:\n"
			"  -C | -P |    Consumer or Producer mode\n"
			"  -G <groupid> High-level Kafka Consumer mode\n"
			"  -t <topic>   Topic to consume / produce\n"
			"  -p <num>     Partition (defaults to random). "
			"Multiple partitions are allowed in -C consumer mode.\n"
			"  -M           Print consumer interval stats\n"
			"  -b <brokers> Broker address list (host[:port],..)\n"
			"  -s <size>    Message size (producer)\n"
			"  -k <key>     Message key (producer)\n"
			"  -c <cnt>     Messages to transmit/receive\n"
			"  -x <cnt>     Hard exit after transmitting <cnt> messages (producer)\n"
			"  -D           Copy/Duplicate data buffer (producer)\n"
			"  -i <ms>      Display interval\n"
			"  -m <msg>     Message payload pattern\n"
			"  -S <start>   Send a sequence number starting at "
			"<start> as payload\n"
			"  -R <seed>    Random seed value (defaults to time)\n"
			"  -a <acks>    Required acks (producer): "
			"-1, 0, 1, >1\n"
			"  -B <size>    Consume batch size (# of msgs)\n"
			"  -z <codec>   Enable compression:\n"
			"               none|gzip|snappy\n"
			"  -o <offset>  Start offset (consumer)\n"
			"               beginning, end, NNNNN or -NNNNN\n"
			"  -d [facs..]  Enable debugging contexts:\n"
			"               %s\n"
			"  -X <prop=name> Set arbitrary librdkafka "
			"configuration property\n"
			"               Properties prefixed with \"topic.\" "
			"will be set on topic object.\n"
			"               Use '-X list' to see the full list\n"
			"               of supported properties.\n"
                        "  -X file=<path> Read config from file.\n"
			"  -T <intvl>   Enable statistics from librdkafka at "
			"specified interval (ms)\n"
                        "  -Y <command> Pipe statistics to <command>\n"
			"  -I           Idle: dont produce any messages\n"
			"  -q           Decrease verbosity\n"
                        "  -v           Increase verbosity (default 1)\n"
                        "  -u           Output stats in table format\n"
                        "  -r <rate>    Producer msg/s limit\n"
                        "  -l           Latency measurement.\n"
                        "               Needs two matching instances, one\n"
                        "               consumer and one producer, both\n"
                        "               running with the -l switch.\n"
                        "  -l           Producer: per-message latency stats\n"
			"  -A <file>    Write per-message latency stats to "
			"<file>. Requires -l\n"
                        "  -O           Report produced offset (producer)\n"
			"  -N           No delivery reports (producer)\n"
			"\n"
			" In Consumer mode:\n"
			"  consumes messages and prints thruput\n"
			"  If -B <..> is supplied the batch consumer\n"
			"  mode is used, else the callback mode is used.\n"
			"\n"
			" In Producer mode:\n"
			"  writes messages of size -s <..> and prints thruput\n"
			"\n",
			argv[0],
			rd_kafka_version_str(), rd_kafka_version(),
			RD_KAFKA_DEBUG_CONTEXTS);
		exit(1);
	}


	dispintvl *= 1000; /* us */

        if (verbosity > 1)
                printf("%% Using random seed %i, verbosity level %i\n",
                       seed, verbosity);
	srand(seed);
	signal(SIGINT, stop);
#ifdef SIGUSR1
	signal(SIGUSR1, sig_usr1);
#endif


	if (debug &&
	    rd_kafka_conf_set(conf, "debug", debug, errstr, sizeof(errstr)) !=
	    RD_KAFKA_CONF_OK) {
		printf("%% Debug configuration failed: %s: %s\n",
		       errstr, debug);
		exit(1);
	}

        /* Always enable stats (for RTT extraction), and if user supplied
         * the -T <intvl> option we let her take part of the stats aswell. */
        rd_kafka_conf_set_stats_cb(conf, stats_cb);

        if (!stats_intvlstr) {
                /* if no user-desired stats, adjust stats interval
                 * to the display interval. */
                rd_snprintf(tmp, sizeof(tmp), "%"PRId64, dispintvl / 1000);
        }

        if (rd_kafka_conf_set(conf, "statistics.interval.ms",
                              stats_intvlstr ? stats_intvlstr : tmp,
                              errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%% %s\n", errstr);
                exit(1);
        }

        if (latency_mode)
                do_seq = 0;

        if (stats_intvlstr) {
                /* User enabled stats (-T) */

#ifndef _MSC_VER
                if (stats_cmd) {
                        if (!(stats_fp = popen(stats_cmd, "we"))) {
                                fprintf(stderr,
                                        "%% Failed to start stats command: "
                                        "%s: %s", stats_cmd, strerror(errno));
                                exit(1);
                        }
                } else
#endif
                        stats_fp = stdout;
        }

	if (msgcnt != -1)
		forever = 0;

	topic = topics->elems[0].topic;

	if (mode == 'P') {
		/*
		 * Producer
		 */
		char *sbuf;
		char *pbuf;
		int outq;
		int keylen = key ? (int)strlen(key) : 0;
		off_t rof = 0;
		size_t plen = strlen(msgpattern);
		int partition = partitions ? partitions[0] :
			RD_KAFKA_PARTITION_UA;

                if (latency_mode) {
                        int minlen = (int)(strlen("LATENCY:") +
                                           strlen("18446744073709551615 ")+1);
                        msgsize = RD_MAX(minlen, msgsize);
                        sendflags |= RD_KAFKA_MSG_F_COPY;
		} else if (do_seq) {
                        int minlen = (int)strlen("18446744073709551615 ")+1;
                        if (msgsize < minlen)
                                msgsize = minlen;

			/* Force duplication of payload */
                        sendflags |= RD_KAFKA_MSG_F_FREE;
		}

		sbuf = malloc(msgsize);

		/* Copy payload content to new buffer */
		while (rof < msgsize) {
			size_t xlen = RD_MIN((size_t)msgsize-rof, plen);
			memcpy(sbuf+rof, msgpattern, xlen);
			rof += (off_t)xlen;
		}

		if (msgcnt == -1)
			printf("%% Sending messages of size %i bytes\n",
			       msgsize);
		else
			printf("%% Sending %i messages of size %i bytes\n",
			       msgcnt, msgsize);

		if (with_dr)
			rd_kafka_conf_set_dr_msg_cb(conf, msg_delivered);

		/* Create Kafka handle */
		if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
 					errstr, sizeof(errstr)))) {
			fprintf(stderr,
				"%% Failed to create Kafka producer: %s\n",
				errstr);
			exit(1);
		}

                global_rk = rk;

		/* Add broker(s) */
		if (brokers && rd_kafka_brokers_add(rk, brokers) < 1) {
			fprintf(stderr, "%% No valid brokers specified\n");
			exit(1);
		}

		/* Explicitly create topic to avoid per-msg lookups. */
		rkt = rd_kafka_topic_new(rk, topic, topic_conf);


                if (rate_sleep && verbosity >= 2)
                        fprintf(stderr,
                                "%% Inter message rate limiter sleep %ius\n",
                                rate_sleep);

                dr_disp_div = msgcnt / 50;
                if (dr_disp_div == 0)
                        dr_disp_div = 10;

		cnt.t_start = cnt.t_last = rd_clock();

		msgs_wait_produce_cnt = msgcnt;

		while (run && (msgcnt == -1 || (int)cnt.msgs < msgcnt)) {
			/* Send/Produce message. */

			if (idle) {
				rd_kafka_poll(rk, 1000);
				continue;
			}

                        if (latency_mode) {
                                rd_snprintf(sbuf, msgsize-1,
                                         "LATENCY:%"PRIu64,  wall_clock());
                        } else if (do_seq) {
                                rd_snprintf(sbuf,
                                         msgsize-1, "%"PRIu64": ", seq);
                                seq++;
			}

			if (sendflags & RD_KAFKA_MSG_F_FREE) {
				/* Duplicate memory */
				pbuf = malloc(msgsize);
				memcpy(pbuf, sbuf, msgsize);
			} else
				pbuf = sbuf;

                        if (msgsize == 0)
                                pbuf = NULL;

			cnt.tx++;
			while (run &&
			       rd_kafka_produce(rkt, partition,
						sendflags, pbuf, msgsize,
						key, keylen, NULL) == -1) {
				rd_kafka_resp_err_t err = rd_kafka_last_error();
				if (err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
					printf("%% No such partition: "
						   "%"PRId32"\n", partition);
				else if (verbosity >= 3 ||
					(err != RD_KAFKA_RESP_ERR__QUEUE_FULL && verbosity >= 1))
					printf("%% produce error: %s%s\n",
						   rd_kafka_err2str(err),
						   err == RD_KAFKA_RESP_ERR__QUEUE_FULL ?
						   " (backpressure)" : "");

				cnt.tx_err++;
				if (err != RD_KAFKA_RESP_ERR__QUEUE_FULL) {
					run = 0;
					break;
				}
				now = rd_clock();
				if (verbosity >= 2 &&
                                    cnt.t_enobufs_last + dispintvl <= now) {
					printf("%% Backpressure %i "
					       "(tx %"PRIu64", "
					       "txerr %"PRIu64")\n",
					       rd_kafka_outq_len(rk),
					       cnt.tx, cnt.tx_err);
					cnt.t_enobufs_last = now;
				}

				/* Poll to handle delivery reports */
				rd_kafka_poll(rk, 10);

                                print_stats(rk, mode, otype, compression);
			}

			msgs_wait_cnt++;
			if (msgs_wait_produce_cnt != -1)
				msgs_wait_produce_cnt--;
			cnt.msgs++;
			cnt.bytes += msgsize;

                        if (rate_sleep) {
				if (rate_sleep > 100) {
#ifdef _MSC_VER
					Sleep(rate_sleep / 1000);
#else
					usleep(rate_sleep);
#endif
				} else {
					rd_ts_t next = rd_clock() + rate_sleep;
					while (next > rd_clock())
						;
				}
                        }

			/* Must poll to handle delivery reports */
			rd_kafka_poll(rk, 0);

			print_stats(rk, mode, otype, compression);
		}

		forever = 0;
                if (verbosity >= 2)
                        printf("%% All messages produced, "
                               "now waiting for %li deliveries\n",
                               msgs_wait_cnt);

		/* Wait for messages to be delivered */
                while (run && rd_kafka_poll(rk, 1000) != -1)
			print_stats(rk, mode, otype, compression);


		outq = rd_kafka_outq_len(rk);
                if (verbosity >= 2)
                        printf("%% %i messages in outq\n", outq);
		cnt.msgs -= outq;
		cnt.bytes -= msgsize * outq;

		cnt.t_end = t_end;

		if (cnt.tx_err > 0)
			printf("%% %"PRIu64" backpressures for %"PRIu64
			       " produce calls: %.3f%% backpressure rate\n",
			       cnt.tx_err, cnt.tx,
			       ((double)cnt.tx_err / (double)cnt.tx) * 100.0);

		/* Destroy topic */
		rd_kafka_topic_destroy(rkt);

		/* Destroy the handle */
		rd_kafka_destroy(rk);
                global_rk = rk = NULL;

		free(sbuf);

                exitcode = cnt.msgs == cnt.msgs_dr_ok ? 0 : 1;

	} else if (mode == 'C') {
		/*
		 * Consumer
		 */

		rd_kafka_message_t **rkmessages = NULL;
		size_t i = 0;

		/* Create Kafka handle */
		if (!(rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf,
					errstr, sizeof(errstr)))) {
			fprintf(stderr,
				"%% Failed to create Kafka consumer: %s\n",
				errstr);
			exit(1);
		}

                global_rk = rk;

		/* Add broker(s) */
		if (brokers && rd_kafka_brokers_add(rk, brokers) < 1) {
			fprintf(stderr, "%% No valid brokers specified\n");
			exit(1);
		}

		/* Create topic to consume from */
		rkt = rd_kafka_topic_new(rk, topic, topic_conf);

		/* Batch consumer */
		if (batch_size)
			rkmessages = malloc(sizeof(*rkmessages) * batch_size);

		/* Start consuming */
		rkqu = rd_kafka_queue_new(rk);
		for (i=0 ; i<(size_t)partition_cnt ; ++i) {
			const int r = rd_kafka_consume_start_queue(rkt,
				partitions[i], start_offset, rkqu);

			if (r == -1) {
                                fprintf(stderr, "%% Error creating queue: %s\n",
                                        rd_kafka_err2str(rd_kafka_last_error()));
				exit(1);
			}
		}

		while (run && (msgcnt == -1 || msgcnt > (int)cnt.msgs)) {
			/* Consume messages.
			 * A message may either be a real message, or
			 * an error signaling (if rkmessage->err is set).
			 */
			uint64_t fetch_latency;
			ssize_t r;

			fetch_latency = rd_clock();

			if (batch_size) {
				int i;
				int partition = partitions ? partitions[0] :
				    RD_KAFKA_PARTITION_UA;

				/* Batch fetch mode */
				r = rd_kafka_consume_batch(rkt, partition,
							   1000,
							   rkmessages,
							   batch_size);
				if (r != -1) {
					for (i = 0 ; i < r ; i++) {
						msg_consume(rkmessages[i],
							NULL);
						rd_kafka_message_destroy(
							rkmessages[i]);
					}
				}
			} else {
				/* Queue mode */
				r = rd_kafka_consume_callback_queue(rkqu, 1000,
							msg_consume,
							NULL);
			}

			cnt.t_fetch_latency += rd_clock() - fetch_latency;
                        if (r == -1)
                                fprintf(stderr, "%% Error: %s\n",
                                        rd_kafka_err2str(rd_kafka_last_error()));

			print_stats(rk, mode, otype, compression);

			/* Poll to handle stats callbacks */
			rd_kafka_poll(rk, 0);
		}
		cnt.t_end = rd_clock();

		/* Stop consuming */
		for (i=0 ; i<(size_t)partition_cnt ; ++i) {
			int r = rd_kafka_consume_stop(rkt, (int32_t)i);
			if (r == -1) {
                                fprintf(stderr,
                                        "%% Error in consume_stop: %s\n",
                                        rd_kafka_err2str(rd_kafka_last_error()));
			}
		}
		rd_kafka_queue_destroy(rkqu);

		/* Destroy topic */
		rd_kafka_topic_destroy(rkt);

		if (batch_size)
			free(rkmessages);

		/* Destroy the handle */
		rd_kafka_destroy(rk);

                global_rk = rk = NULL;

	} else if (mode == 'G') {
		/*
		 * High-level balanced Consumer
		 */
		rd_kafka_resp_err_t err;

		rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);
		rd_kafka_conf_set_default_topic_conf(conf, topic_conf);

		/* Create Kafka handle */
		if (!(rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf,
					errstr, sizeof(errstr)))) {
			fprintf(stderr,
				"%% Failed to create Kafka consumer: %s\n",
				errstr);
			exit(1);
		}

		/* Forward all events to consumer queue */
		rd_kafka_poll_set_consumer(rk);

                global_rk = rk;

		/* Add broker(s) */
		if (brokers && rd_kafka_brokers_add(rk, brokers) < 1) {
			fprintf(stderr, "%% No valid brokers specified\n");
			exit(1);
		}

		err = rd_kafka_subscribe(rk, topics);
		if (err) {
			fprintf(stderr, "%% Subscribe failed: %s\n",
				rd_kafka_err2str(err));
			exit(1);
		}
		fprintf(stderr, "%% Waiting for group rebalance..\n");

		while (run && (msgcnt == -1 || msgcnt > (int)cnt.msgs)) {
			/* Consume messages.
			 * A message may either be a real message, or
			 * an event (if rkmessage->err is set).
			 */
			rd_kafka_message_t *rkmessage;
			uint64_t fetch_latency;

			fetch_latency = rd_clock();

			rkmessage = rd_kafka_consumer_poll(rk, 1000);
			if (rkmessage) {
				msg_consume(rkmessage, NULL);
				rd_kafka_message_destroy(rkmessage);
			}

			cnt.t_fetch_latency += rd_clock() - fetch_latency;

			print_stats(rk, mode, otype, compression);
		}
		cnt.t_end = rd_clock();

		err = rd_kafka_consumer_close(rk);
		if (err)
			fprintf(stderr, "%% Failed to close consumer: %s\n",
				rd_kafka_err2str(err));

		rd_kafka_destroy(rk);
	}

	print_stats(NULL, mode, otype|_OTYPE_FORCE, compression);

	if (cnt.t_fetch_latency && cnt.msgs)
		printf("%% Average application fetch latency: %"PRIu64"us\n",
		       cnt.t_fetch_latency / cnt.msgs);

	if (latency_fp)
		fclose(latency_fp);

        if (stats_fp) {
#ifndef _MSC_VER
                pclose(stats_fp);
#endif
                stats_fp = NULL;
        }

        if (partitions)
                free(partitions);

	rd_kafka_topic_partition_list_destroy(topics);

	/* Let background threads clean up and terminate cleanly. */
	rd_kafka_wait_destroyed(2000);

	return exitcode;
}

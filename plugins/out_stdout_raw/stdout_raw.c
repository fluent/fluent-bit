/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
 *
 *  Modified Work:
 *
 *  Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 *  This software product is a proprietary product of NVIDIA CORPORATION &
 *  AFFILIATES (the "Company") and all right, title, and interest in and to the
 *  software product, including all associated intellectual property rights, are
 *  and shall remain exclusively with the Company.
 *
 *  This software product is governed by the End User License Agreement
 *  provided with the software product.
 *
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>
#include <time.h>

#include "stdout_raw.h"
#include "stdio.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <ctype.h>


bool is_name_corrupted(const char * name, size_t name_len) {
    int i;
    for (i = 0; i < name_len; i++) {
        char c = name[i];
        if (!(isalpha(c) || isdigit(c) || c == '_' || c == '.')){
            return true;
        }
    }
    return false;
}


void check_msgpack_keys_stdout_raw(FILE* out, msgpack_object o, bool iskey, int* num_fields, const char* tag_key, char** tag_val) {
    switch(o.type) {
    case MSGPACK_OBJECT_STR:
        if (!iskey) {
            break;
        }
        bool corrupted = is_name_corrupted(o.via.str.ptr, o.via.str.size);
        *num_fields += 1;

        if (corrupted) {
            fprintf(out, "key=\"");
            fwrite(o.via.str.ptr, o.via.str.size, 1, out);
            fprintf(out, "\"");
            fprintf(out, " -> CORRUPTED\n");
        }
        break;
    case MSGPACK_OBJECT_ARRAY:
        if(o.via.array.size != 0) {
            msgpack_object* p = o.via.array.ptr;
            msgpack_object* const pend = o.via.array.ptr + o.via.array.size;
            check_msgpack_keys_stdout_raw(out, *p, false, num_fields, tag_key, tag_val);
            ++p;
            for(; p < pend; ++p) {
                check_msgpack_keys_stdout_raw(out, *p, false, num_fields, tag_key, tag_val);
            }
        }
        break;
    case MSGPACK_OBJECT_MAP:
        if(o.via.map.size != 0) {
            msgpack_object_kv* p = o.via.map.ptr;
            msgpack_object_kv* const pend = o.via.map.ptr + o.via.map.size;

            // if (strncmp(tag_key, p->key.via.str.ptr, p->key.via.str.size) == 0) {
            //     strncpy(*tag_val, p->val.via.str.ptr, p->val.via.str.size);
            //     *tag_val[p->val.via.str.size] = '\0';
            // }
            check_msgpack_keys_stdout_raw(out, p->key, true, num_fields, tag_key, tag_val);
            check_msgpack_keys_stdout_raw(out, p->val, false, num_fields, tag_key, tag_val);
            ++p;
            for(; p < pend; ++p) {
                if (strncmp(tag_key, p->key.via.str.ptr, strlen(tag_key)) == 0) {
                    char tmp[128];
                    strncpy(tmp, p->val.via.str.ptr, p->val.via.str.size);
                    tmp[p->val.via.str.size] = '\0';
                    *tag_val = strdup(tmp);

                }
                check_msgpack_keys_stdout_raw(out, p->key, true, num_fields, tag_key, tag_val);
                check_msgpack_keys_stdout_raw(out, p->val, false, num_fields, tag_key, tag_val);
            }
        }
        break;
    default:{
    };
    }
}


record_counters_t* create_record_counters() {
    record_counters_t* rc = calloc(1, sizeof(record_counters_t));
    rc->num_types = 0;
    rc->type_name = (type_name_t *) calloc(1, sizeof(type_name_t));
    rc->num_records = (int *) calloc(1, sizeof(int));
    rc->num_records[0] = 0;
    rc->num_fields_per_record = (int **) calloc(1, sizeof(int*));
    rc->num_fields_per_record[0] = (int*) calloc(1, sizeof(int));
    return rc;
}


void destroy_record_counters(record_counters_t* rc) {
    int i;
    if (rc->type_name) {
        free(rc->type_name);
    }
    if (rc->num_fields_per_record) {
        for (i = 0; i < rc->num_types; i++) {
            if (rc->num_fields_per_record[i]) {
                free(rc->num_fields_per_record[i]);
            }
        }
        free(rc->num_fields_per_record);
    }
    if (rc->num_records) {
        free(rc->num_records);
    }
}


void update_record_counters(record_counters_t* rc, msgpack_object o) {
    int num_record_fields = 0;
    char *type_name = NULL;
    check_msgpack_keys_stdout_raw(stdout, o, false, &num_record_fields, "type_name", &type_name);
    if (!type_name) {
        type_name = strdup("counters");
        type_name[8] = '\0';
    }

    int i = 0;
    void* tmp;
    for (i = 0; i < rc->num_types; i++) {
        if (strcmp(type_name, rc->type_name[i]) == 0) {
            break;
        }
    }

    if (i == rc->num_types) {
        // new type name;
        sprintf(rc->type_name[rc->num_types], "%s", type_name);
        rc->num_types += 1;

        tmp = realloc(rc->type_name, (rc->num_types+1) * (sizeof(type_name_t)));
        if (tmp) {
            rc->type_name = (type_name_t *) tmp;
        }

        tmp = realloc(rc->num_records, rc->num_types * (sizeof(char*)));
        if (tmp) {
            rc->num_records = (int*) tmp;
            rc->num_records[rc->num_types-1] = 1;
        }

        int cur_num_rec = rc->num_records[i];
        rc->num_fields_per_record[i][cur_num_rec - 1] = num_record_fields;
        tmp = realloc(rc->num_fields_per_record[i], (cur_num_rec+1) * (sizeof(int*)));
        if (tmp) {
            rc->num_fields_per_record[i] = (int*) tmp;
        }

        tmp = realloc(rc->num_fields_per_record, (rc->num_types + 1) * (sizeof(int*)));
        if (tmp) {
            rc->num_fields_per_record = (int**) tmp;
            rc->num_fields_per_record[rc->num_types] = (int*) calloc(1, sizeof(int));
        }
    } else {
        int cur_num_rec = rc->num_records[i];
        rc->num_fields_per_record[i][cur_num_rec] = num_record_fields;
        tmp = realloc(rc->num_fields_per_record[i], (cur_num_rec + 1) * (sizeof(int*)));
        if (tmp) {
            rc->num_fields_per_record[i] = (int*) tmp;
        }

        rc->num_records[i]++;
    }

    if (type_name) {
        free(type_name);
    }
}

void print_record_counters(FILE* fd, record_counters_t* rc) {
    int total_records = 0;
    int i, j;
    for (i = 0; i < rc->num_types; i++ ) {
        total_records += rc->num_records[i];
        fprintf(fd, "[%s] %d\n", rc->type_name[i], rc->num_records[i]);
        fprintf(fd, "fields:");
        for (j = 0; j < rc->num_records[i]; j++) {
            fprintf(fd, " %d", rc->num_fields_per_record[i][j]);
        }
        fprintf(fd, "\n");
    }
    fprintf(fd, "[total] %d\n\n", total_records);
}


static int cb_stdout_raw_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_stdout_raw *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_stdout_raw));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->total_num_received_records = 0;
    ctx->global_record_cnt = 0;


    ctx->out_stream = stdout;
    tmp = flb_output_get_property("stream", ins);

    if (tmp) {
        if (strcmp(tmp, "stdout") == 0) {
            ctx->out_stream = stdout;
            flb_plg_info(ctx->ins, "out_stream = stdout");
        } else if (strcmp(tmp,"stderr") == 0) {
            ctx->out_stream = stderr;
            flb_plg_info(ctx->ins, "out_stream = stderr");
        } else { // stream to file
            FILE* stream_file = fopen(tmp, "w");
            if (!stream_file) {
                flb_errno();
                flb_free(ctx);
                return -1;
            }
            ctx->out_stream = stream_file;
            flb_plg_info(ctx->ins, "out_stream = %s", tmp);
        }
    } else {
        flb_plg_info(ctx->ins, "no stream found. using default stdout");
    }


    ctx->bytes_milestone = 1024*1024; // default is 1 MB
    tmp = flb_output_get_property("measure_speed_MB_milestone", ins);
    if (tmp) {
        ctx->bytes_milestone = atoi(tmp) * 1024 * 1024;
    }

    ctx->measure_speed = false;
    tmp = flb_output_get_property("measure_speed", ins);
    if (tmp) {
        if (flb_utils_bool(tmp) == FLB_TRUE) {
            ctx->measure_speed  = 1;
            ctx->ts_begin       = 0;
            ctx->ts_end         = 0;
            ctx->bytes_received = 0;

            flb_plg_info(ctx->ins, "Speed measurements will be printed each %"PRIu64" bytes (%"PRIu64" MB)",
                         ctx->bytes_milestone, ctx->bytes_milestone/1024/1024);
        }
    }

    ctx->use_bin_file_check = 0;
    tmp = flb_output_get_property("check_dir", ins);
    if (tmp) {
        ctx->use_bin_file_check = 1;
        ctx->check_dir = strdup(tmp);

        ctx->check_file_path[0] = '\0';
        sprintf(ctx->check_file_path, "%s/clx_test_recv_data.bin", ctx->check_dir);
        ctx->fieds_counter_log_path[0] = '\0';
        sprintf(ctx->fieds_counter_log_path, "%s/clx_export_recv_records.bin", ctx->check_dir);
    }
    if (ctx->use_bin_file_check) {
        ctx->log_fields_count_fd = fopen(ctx->fieds_counter_log_path, "ab");
        if (ctx->log_fields_count_fd == NULL) {
            flb_plg_warn(ctx->ins, "Cannot opend %s. Disabling logs.\n", ctx->fieds_counter_log_path);
            ctx->use_bin_file_check = 0;
        } else {
            fprintf(ctx->log_fields_count_fd, "Records:\n");
            ctx->record_counters = create_record_counters();
        }
    }
    if (ctx->use_bin_file_check) {
        FILE *fp = fopen(ctx->check_file_path, "ab");
        if (fp == NULL) {
            flb_plg_warn(ctx->ins, "Cannot opend %s. Disabling logs.\n", ctx->check_file_path);
            ctx->use_bin_file_check = 0;
        } else {
            ctx->check_in_raw_msgpack_fd = fileno(fp);
        }
    }


    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'format' option. "
                          "Using 'msgpack'");
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
                          "Using 'double' type", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

#ifdef __x86_64__
static uint64_t clx_parse_cpuinfo(void) {
    float f = 1.0;
    char buf[256];

    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(buf, 256, fp)) {
            if (!strncmp(buf, "model name", 10)) {
                char* p = strchr(buf, '@');
                if (p) {
                    sscanf(++p, "%f", &f);
                }
                break;
            }
        }
        fclose(fp);
    }
    if (f < 1.0) {
        f = 1.0;  // if cannot get correct frequency - use TSC
        fprintf(stderr, "Could not get correct value of frequency. Values are in ticks.");
    } else {
        f *= 1.0e9;  // Value in 'model name' is in GHz
    }
    return (uint64_t)f;
}

static  uint64_t get_cpu_freq(void) {
#ifdef USE_SLEEP_TO_GET_CPU_FREQUENCY
    // Note:  Recent Intel CPUs have the TSC running at constant frequency.
    static uint64_t clock = 0;
    if (clock == 0) {
        uint64_t t_start = read_hres_clock();
        sleep(1);
        uint64_t t_end = read_hres_clock();
        clock = t_end - t_start;
    }
    return clock;
#else
    return clx_parse_cpuinfo();
#endif
}


static inline uint64_t read_hres_clock(void) {
    uint32_t low, high;
    asm volatile ("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | (uint64_t)low;
}


uint64_t clx_convert_cycles_to_usec(uint64_t cycles) {
    static uint64_t freq = 0;
    if (freq < 1) {
        // initialize once
        freq = get_cpu_freq();
        if (freq == 1) {
            freq = 1e6;  // time will be in ticks
        }
    }
    uint64_t ret = cycles * 1e6 / freq;
    return ret;
}


static void measure_recv_speed(const void *data, size_t bytes, struct flb_stdout_raw *ctx) {
    if (ctx->ts_begin == 0) {
        // set ts_begin on first data
        ctx->ts_begin = read_hres_clock();
    }

    ctx->bytes_received += bytes;

    if (ctx->bytes_received > ctx->bytes_milestone) {
        ctx->ts_end = read_hres_clock();
        uint64_t t_diff_clocks = ctx->ts_end - ctx->ts_begin;
        uint64_t time_diff = clx_convert_cycles_to_usec(t_diff_clocks);

        flb_plg_info(ctx->ins, "received %"PRIu64" bytes in %"PRIu64" usec\n", ctx->bytes_received, time_diff );

        ctx->bytes_received = 0;
        ctx->ts_begin = ctx->ts_end;
    }
}
#endif  // __x86_64__


static void cb_stdout_raw_flush(struct flb_event_chunk *event_chunk,
                                struct flb_output_flush *out_flush,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    struct flb_stdout_raw *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) i_ins;
    (void) config;

    if (ctx->measure_speed) {
#ifdef __x86_64__
        measure_recv_speed(event_chunk->data, event_chunk->size, ctx);
#endif
    } else {


        if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
            json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                                   event_chunk->size,
                                                   ctx->out_format,
                                                   ctx->json_date_format,
                                                   ctx->date_key);
            write(STDOUT_FILENO, json, flb_sds_len(json));
            flb_sds_destroy(json);

            /*
            * If we are 'not' in json_lines mode, we need to add an extra
            * breakline.
            */
            if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
                fprintf(stdout, "\n");
            }
            fflush(stdout);
        } else {
            msgpack_unpacked_init(&result);
            while (msgpack_unpack_next(&result, event_chunk->data,
                                       event_chunk->size, &off) == MSGPACK_UNPACK_SUCCESS) {
                fprintf(ctx->out_stream, "[%zd] %s: ", ctx->global_record_cnt++, event_chunk->tag);
                msgpack_object_print(ctx->out_stream, result.data);
                fprintf(ctx->out_stream, "\n");

                if (ctx->use_bin_file_check) {
                    ctx->total_num_received_records++;
                    update_record_counters(ctx->record_counters, result.data);
                }
            }

            msgpack_unpacked_destroy(&result);
            flb_free(buf);
        }

        fflush(ctx->out_stream);
    }  // measure_speed

    if (ctx->use_bin_file_check) {
        // to check that we recieved all data from in_raw_msgpack
        if (ctx->check_in_raw_msgpack_fd) {
            write(ctx->check_in_raw_msgpack_fd, event_chunk->data, event_chunk->size);
        }
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_stdout_raw_exit(void *data, struct flb_config *config)
{
    struct flb_stdout_raw *ctx = data;
    if (!ctx) {
        return 0;
    }
    if (ctx->use_bin_file_check) {

        if (ctx->check_dir) {
            free(ctx->check_dir);
        }
        if (ctx->check_in_raw_msgpack_fd) {
            close(ctx->check_in_raw_msgpack_fd);
        }
        if (ctx->log_fields_count_fd) {
            print_record_counters(ctx->log_fields_count_fd, ctx->record_counters);
            fclose(ctx->log_fields_count_fd);
        }
        if (ctx->record_counters) {
            destroy_record_counters(ctx->record_counters);
        }
        if (ctx->out_stream != stdout && ctx->out_stream != stderr) {
            fclose(ctx->out_stream);
        }
    }
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "check_dir", NULL,
     0, FLB_FALSE, 0,
     "Specifies the output dir to check end-to-end data transfer."
    },
    {
     FLB_CONFIG_MAP_BOOL, "stream", NULL,
     0, FLB_FALSE, 0,
     "Stream destination: file name, stdout, or stderr. Default is stdout."
    },
    {
     FLB_CONFIG_MAP_BOOL, "measure_speed", false,
     0, FLB_FALSE, 0,
     "Specifies speed measuring mode. Disables data dumping."
    },
    {
     FLB_CONFIG_MAP_INT, "measure_speed_MB_milestone", NULL,
     0, FLB_FALSE, 0,
     "Specifies speed measuring parameter. Measurings will be printed each MB_milestone megabytes"
    },
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the data format to be printed. Supported formats are msgpack json, json_lines and json_stream."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout_raw, json_date_key),
    "Specifies the format of the date. Supported formats are double, iso8601 and epoch."
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_stdout_raw_plugin = {
    .name         = "stdout_raw",
    .description  = "Prints raw msgpack data withot timestamp to STDOUT",
    .cb_init      = cb_stdout_raw_init,
    .cb_flush     = cb_stdout_raw_flush,
    .cb_exit      = cb_stdout_raw_exit,
    .flags        = 0,
    .config_map   = config_map
};

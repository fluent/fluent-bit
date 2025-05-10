/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#ifndef FLB_UTILS_H
#define FLB_UTILS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>

struct flb_split_entry {
    char *value;
    int len;
    off_t last_pos;
    struct mk_list _head;
};

void flb_utils_error(int err);
void flb_utils_error_c(const char *msg);
void flb_utils_warn_c(const char *msg);
void flb_message(int type, const char *file, int line, const char *fmt, ...);

#ifdef FLB_HAVE_FORK
int flb_utils_set_daemon(struct flb_config *config);
#endif

void flb_utils_print_setup(struct flb_config *config);

struct mk_list *flb_utils_split(const char *line, int separator, int max_split);
struct mk_list *flb_utils_split_quoted(const char *line, int separator, int max_split);
void flb_utils_split_free_entry(struct flb_split_entry *entry);
void flb_utils_split_free(struct mk_list *list);
int flb_utils_timer_consume(flb_pipefd_t fd);
int64_t flb_utils_size_to_bytes(const char *size);
int64_t flb_utils_hex2int(char *hex, int len);
int flb_utils_time_to_seconds(const char *time);
int flb_utils_pipe_byte_consume(flb_pipefd_t fd);
int flb_utils_bool(const char *val);
void flb_utils_bytes_to_human_readable_size(size_t bytes,
                                            char *out_buf, size_t size);
int flb_utils_time_split(const char *time, int *sec, long *nsec);
int flb_utils_write_str(char *buf, int *off, size_t size,
                        const char *str, size_t str_len);
int flb_utils_write_str_buf(const char *str, size_t str_len,
                            char **out, size_t *out_size);

int flb_utils_url_split(const char *in_url, char **out_protocol,
                        char **out_host, char **out_port, char **out_uri);
int flb_utils_proxy_url_split(const char *in_url, char **out_protocol,
                              char **out_username, char **out_password,
                              char **out_host, char **out_port);
int flb_utils_read_file(char *path, char **out_buf, size_t *out_size);
int flb_utils_read_file_offset(char *path, off_t offset_start, off_t offset_end, char **out_buf, size_t *out_size);
char *flb_utils_get_os_name();
int flb_utils_uuid_v4_gen(char *buf);
int flb_utils_get_machine_id(char **out_id, size_t *out_size);
void flb_utils_set_plugin_string_property(const char *name,
                                          flb_sds_t *field_storage,
                                          flb_sds_t  new_value);
int flb_utils_mkdir(const char *dir, int perms);
int flb_utils_url_split_sds(const flb_sds_t in_url, flb_sds_t *out_protocol,
                            flb_sds_t *out_host, flb_sds_t *out_port, flb_sds_t *out_uri);

#endif

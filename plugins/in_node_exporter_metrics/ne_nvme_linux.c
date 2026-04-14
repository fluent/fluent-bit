/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>


static int nvme_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* node_nvme_info */
    g = cmt_gauge_create(ctx->cmt, "node", "nvme", "info",
                         "Non-numeric data from /sys/class/nvme/<device>",
                         5, (char *[]){"device", "firmware_revision", "model", "serial", "state"});
    if (!g) {
        return -1;
    }
    ctx->nvme_info = g;

    return 0;
}

static int check_path_for_sysfs(struct flb_ne *ctx, const char *prefix, const char *path)
{
    int len;
    flb_sds_t p;

    /* Compose the proc path */
    p = flb_sds_create(prefix);
    if (!p) {
        return -1;
    }

    if (path) {
        flb_sds_cat_safe(&p, "/", 1);
        len = strlen(path);
        flb_sds_cat_safe(&p, path, len);
    }

    if (access(p, F_OK) == -1 &&
        (errno == ENOENT || errno == ESRCH)) {
        flb_plg_debug(ctx->ins, "error reading stat for path %s. errno = %d", p, errno);
        flb_sds_destroy(p);

        return -1;
    }

    flb_sds_destroy(p);
    return 0;
}

struct nvme_sys_info {
    char *name;
    char *serial;
    char *model;
    char *state;
    char *firmware_revision;
};

static void cleanup_nvme_sys_info(struct nvme_sys_info *info)
{
    if (info == NULL) {
        return;
    }

    /* Note: name member is not allocated. Just for using reference. */
    flb_sds_destroy(info->serial);
    flb_sds_destroy(info->model);
    flb_sds_destroy(info->state);
    flb_sds_destroy(info->firmware_revision);
}

static int nvme_get_entry_value(struct flb_ne *ctx,
                                char *entry_path,
                                struct flb_slist_entry *nvme_info,
                                struct mk_list *out_info_list)
{
    int ret;
    char nvme_sysentry[PATH_MAX];
    snprintf(nvme_sysentry, sizeof(nvme_sysentry) - 1, "/%s", entry_path);

    if (check_path_for_sysfs(ctx, nvme_info->str, entry_path) != 0) {
        return -1;
    }
    ret = ne_utils_file_read_lines(nvme_info->str, nvme_sysentry, out_info_list);
    if (ret == -1) {
        return ret;
    }

    return 0;
}

static int nvme_update(struct flb_ne *ctx)
{
    int ret;
    flb_sds_t device_str;
    flb_sds_t tmp;
    const char *pattern = "/nvme[0-9]*";
    struct mk_list *head;
    struct mk_list nvme_class_list;
    struct mk_list nvme_firmware;
    struct mk_list nvme_model;
    struct mk_list nvme_serial;
    struct mk_list nvme_state;
    struct flb_slist_entry *nvme_info;
    struct flb_slist_entry *entry;
    uint64_t ts;
    char *nvme_class_path = "/sys/class/nvme";
    struct nvme_sys_info nvme_sinfo = {
        .name = "",
        .serial = "",
        .model = "",
        .state = "",
        .firmware_revision = ""
    };

    if (access(nvme_class_path, F_OK) == -1 &&
        errno == ENOENT) {
        flb_plg_debug(ctx->ins, "NVMe storage is not mounted");

        return 0;
    }

    mk_list_init(&nvme_class_list);

    ts = cfl_time_now();

    /* scan nvme entries */
    ret = ne_utils_path_scan(ctx, nvme_class_path, pattern, NE_SCAN_DIR, &nvme_class_list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&nvme_class_list) == 0) {
        return 0;
    }

    mk_list_foreach(head, &nvme_class_list) {
        nvme_info = mk_list_entry(head, struct flb_slist_entry, _head);
        device_str = nvme_info->str + strlen(nvme_class_path) + 1;
        nvme_sinfo.name = device_str;

        mk_list_init(&nvme_firmware);
        if (nvme_get_entry_value(ctx, "firmware_rev", nvme_info, &nvme_firmware) == 0) {
            entry = mk_list_entry_first(&nvme_firmware, struct flb_slist_entry, _head);
            tmp = flb_sds_create_len(entry->str, strlen(entry->str));
            flb_sds_trim(tmp);
            nvme_sinfo.firmware_revision = tmp;
        }

        mk_list_init(&nvme_model);
        if (nvme_get_entry_value(ctx, "model", nvme_info, &nvme_model) == 0) {
            entry = mk_list_entry_first(&nvme_model, struct flb_slist_entry, _head);
            tmp = flb_sds_create_len(entry->str, strlen(entry->str));
            flb_sds_trim(tmp);
            nvme_sinfo.model = tmp;
        }

        mk_list_init(&nvme_serial);
        if (nvme_get_entry_value(ctx, "serial", nvme_info, &nvme_serial) == 0) {
            entry = mk_list_entry_first(&nvme_serial, struct flb_slist_entry, _head);
            tmp = flb_sds_create_len(entry->str, strlen(entry->str));
            flb_sds_trim(tmp);
            nvme_sinfo.serial = tmp;
        }

        mk_list_init(&nvme_state);
        if (nvme_get_entry_value(ctx, "state", nvme_info, &nvme_state) == 0) {
            entry = mk_list_entry_first(&nvme_state, struct flb_slist_entry, _head);
            tmp = flb_sds_create_len(entry->str, strlen(entry->str));
            flb_sds_trim(tmp);
            nvme_sinfo.state = tmp;
        }

        cmt_gauge_set(ctx->nvme_info, ts, 1,
                      5, (char *[]){ nvme_sinfo.name, nvme_sinfo.firmware_revision, nvme_sinfo.model,
                                     nvme_sinfo.serial, nvme_sinfo.state});

        flb_slist_destroy(&nvme_firmware);
        flb_slist_destroy(&nvme_model);
        flb_slist_destroy(&nvme_serial);
        flb_slist_destroy(&nvme_state);

        cleanup_nvme_sys_info(&nvme_sinfo);
    }
    flb_slist_destroy(&nvme_class_list);

    return 0;
}


static int ne_nvme_init(struct flb_ne *ctx)
{
    nvme_configure(ctx);
    return 0;
}

static int ne_nvme_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    nvme_update(ctx);
    return 0;
}

struct flb_ne_collector nvme_collector = {
    .name = "nvme",
    .cb_init = ne_nvme_init,
    .cb_update = ne_nvme_update,
    .cb_exit = NULL
};

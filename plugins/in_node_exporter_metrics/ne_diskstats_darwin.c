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

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#endif

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFNumber.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CoreFoundation.h>

#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOBlockStorageDriver.h>

#include <AvailabilityMacros.h>

#if (MAC_OS_X_VERSION_MIN_REQUIRED < 120000)
    /* If deployent target is before macOS 12.0, use the old name. */
    #define IOMainPort IOMasterPort
#endif

#define TARGET_METRICS 11
#define DRIVE_NAME_LEN 31

struct dt_metric {
    void *metric;
    double factor;
};

static void metric_cache_set(struct flb_ne *ctx, void *metric, double factor, int *offset)
{
    int id;
    struct dt_metric *m;
    struct dt_metric **cache;

    id = *offset;

    cache = (struct dt_metric **) ctx->dt_metrics;
    m = (struct dt_metric *) &cache[id];
    m->metric = metric;
    m->factor = factor;
    (*offset)++;
}

static void metric_cache_update(struct flb_ne *ctx, int id, flb_sds_t device,
                                double val)
{
    int ret = -1;
    uint64_t ts;
    struct dt_metric *m;
    struct dt_metric **cache;
    struct cmt_counter *c;

    cache = (struct dt_metric **) ctx->dt_metrics;
    m = (struct dt_metric *) &cache[id];

    ts = cfl_time_now();

    if (m->factor > DBL_EPSILON) {
        val *= m->factor;
    }

    c = (struct cmt_counter *) m->metric;
    ret = cmt_counter_set(c, ts, val, 1, (char *[]) {device});

    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not update metric id '%i', device '%s'",
                      id, device);
    }
}

/* List of the diskstats metrics on macOS
 *
 * 0.  node_disk_reads_completed_total
 * 1.  node_disk_read_sectors_total
 * 2.  node_disk_read_time_seconds_total
 * 3.  node_disk_writes_completed_total
 * 4.  node_disk_written_sectors_total
 * 5.  node_disk_write_time_seconds_total
 * 6.  node_disk_read_bytes_total
 * 7.  node_disk_written_bytes_total
 * 8.  node_disk_read_errors_total
 * 9.  node_disk_write_errors_total
 * 10. node_disk_read_retries_total
 * 11. node_disk_write_retries_total
 *
 */

/* Setup metrics contexts */
static int ne_diskstats_configure(struct flb_ne *ctx)
{
    int offset = 0;
    struct cmt_counter *c;


    /* Create cache for metrics */
    ctx->dt_metrics = flb_calloc(1, sizeof(struct dt_metric) * TARGET_METRICS);
    if (!ctx->dt_metrics) {
        flb_errno();
        return -1;
    }

    /* Initialize regex for skipped devices */
    ctx->dt_regex_skip_devices = flb_regex_create(ctx->dt_regex_skip_devices_text);
    if (!ctx->dt_regex_skip_devices) {
        flb_plg_error(ctx->ins,
                      "could not initialize regex pattern for ignored "
                      "devices: '%s'",
                      IGNORED_DEVICES);
        return -1;
    }

    /* node_disk_reads_completed_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "reads_completed_total",
                           "The total number of reads completed successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_read_sectors_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "reads_sectors_total",
                           "The total number of sectors read successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_read_time_seconds_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "read_time_seconds_total",
                           "The total number of seconds spent by all reads.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_writes_completed_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "writes_completed_total",
                           "The total number of writes completed successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_written_sectors_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "written_sectors_total",
                           "The total number of sectors written successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_write_time_seconds_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "write_time_seconds_total",
                           "This is the total number of seconds spent by all writes.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_read_bytes_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "read_bytes_total",
                           "The total number of read bytes successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_written_bytes_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "written_bytes_total",
                           "The total number of written bytes successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_read_errors_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "read_errors_total",
                           "The total number of read errors.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_write_errors_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "write_errors_total",
                           "The total number of write errors.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_read_retries_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "read_retries_total",
                           "The total number of read retries.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_write_retries_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "write_retries_total",
                           "The total number of write errors.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    return 0;
}


static int skip_device(struct flb_ne *ctx, flb_sds_t device)
{
    return flb_regex_match(ctx->dt_regex_skip_devices,
                           (unsigned char *) device, flb_sds_len(device));
}

static int diskstats_update(struct flb_ne *ctx)
{
    char drive_name[DRIVE_NAME_LEN+1];
    flb_sds_t device;
    mach_port_t iokit_port = MACH_PORT_NULL;
    io_iterator_t drive_list;
    io_registry_entry_t drive, media;
    CFMutableDictionaryRef properties = NULL;
    CFDictionaryRef statistics;
    CFNumberRef number;
    CFStringRef name;
    int64_t value;
    kern_return_t err;
    int64_t blocksize;

    err = IOMainPort(bootstrap_port, &iokit_port);

    if (err != KERN_SUCCESS) {
        flb_plg_error(ctx->ins, "calling IOMainPort is failed");

        return -1;
    }

    /* Get the list of all drives */
    if (IOServiceGetMatchingServices(iokit_port,
                                     IOServiceMatching("IOBlockStorageDriver"),
                                     &drive_list)) {
        flb_plg_error(ctx->ins, "calling IOBlockStorageDirver is failed");

        return -1;


    }

    while ((drive = IOIteratorNext(drive_list)) != 0) {
        properties = NULL;

        err = IORegistryEntryGetChildEntry(drive, kIOServicePlane, &media);
        if (err != KERN_SUCCESS) {
            IOObjectRelease(drive);
            flb_plg_warn(ctx->ins, "calling IORegistryEntryGetChildEntry is failed");

            continue;
        }

        if (IORegistryEntryCreateCFProperties(media, (CFMutableDictionaryRef *)&properties,
                                              kCFAllocatorDefault, kNilOptions) == KERN_SUCCESS) {
            name = (CFStringRef)CFDictionaryGetValue(properties,
                                                     CFSTR(kIOBSDNameKey));
            if (name != NULL) {
                CFStringGetCString(name, drive_name, DRIVE_NAME_LEN, CFStringGetSystemEncoding());
                device = flb_sds_create_len(drive_name, strlen(drive_name));
                if (skip_device(ctx, device)) {
                    flb_plg_debug(ctx->ins, "skip device: %s", device);
                    flb_sds_destroy(device);

                    continue;
                }
            }
            else {
                device = flb_sds_create_len("(unknown)", strlen("(unknown)"));
            }
        }

        /* Get blocksize */
        number = (CFNumberRef)CFDictionaryGetValue(properties, CFSTR(kIOMediaPreferredBlockSizeKey));
        CFNumberGetValue(number, kCFNumberSInt64Type, &blocksize);

        /* Teardown */
        CFRelease(properties);
        IOObjectRelease(media);

        /* Get the properties of this drive */
        if (IORegistryEntryCreateCFProperties(drive, &properties,
                                              kCFAllocatorDefault, kNilOptions) != KERN_SUCCESS) {
            IOObjectRelease(drive);
            IOObjectRelease(drive_list);
            flb_sds_destroy(device);
            flb_plg_error(ctx->ins, "calling IORegistryEntryCreateCFProperties is failed");

            return -1;
        }

        if (!properties) {
            IOObjectRelease(drive);
            flb_sds_destroy(device);

            continue;
        }

        /* Get the statistics of this drive */
        statistics = (CFDictionaryRef)CFDictionaryGetValue(properties,
                                                           CFSTR(kIOBlockStorageDriverStatisticsKey));

        if (!statistics) {
            CFRelease(properties);
            IOObjectRelease(drive);
            flb_sds_destroy(device);

            continue;
        }

        /* Get number of read and sectors read */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsReadsKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 0, device, (double)value);
            metric_cache_update(ctx, 1, device, (double)value/blocksize);
        }

        /* Get number of write and sectors write  */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsWritesKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 3, device, (double)value);
            metric_cache_update(ctx, 4, device, (double)value/blocksize);
        }

        /* Get bytes read */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsBytesReadKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 6, device, (double)value);
        }

        /* Get bytes written */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 7, device, (double)value);
        }

        /* Get total read time (in seconds) */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsTotalReadTimeKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 2, device, (double)value/1e9);
        }

        /* Get total write time (in seconds) */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsTotalWriteTimeKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 5, device, (double)value/1e9);
        }

        /* Get read errors */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsReadErrorsKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 8, device, (double)value);
        }

        /* Get write errors */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsWriteErrorsKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 9, device, (double)value);
        }

        /* Get read retries */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsReadRetriesKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 10, device, (double)value);
        }

        /* Get write retries */
        number = (CFNumberRef)CFDictionaryGetValue(statistics,
                                                   CFSTR(kIOBlockStorageDriverStatisticsWriteRetriesKey));
        if (number != 0) {
            CFNumberGetValue(number, kCFNumberSInt64Type, &value);
            metric_cache_update(ctx, 11, device, (double)value);
        }

        flb_sds_destroy(device);
        CFRelease(properties);
        IOObjectRelease(drive);
    }

    if (drive_list) {
        IOObjectRelease(drive_list);
    }

    if (iokit_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), iokit_port);
        iokit_port = MACH_PORT_NULL;
    }

    return 0;
}

static int ne_diskstats_init(struct flb_ne *ctx)
{
    ne_diskstats_configure(ctx);
    return 0;
}

static int ne_diskstats_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;
    diskstats_update(ctx);
    return 0;
}

static int ne_diskstats_exit(struct flb_ne *ctx)
{
    flb_free(ctx->dt_metrics);
    if (ctx->dt_regex_skip_devices) {
        flb_regex_destroy(ctx->dt_regex_skip_devices);
    }
    return 0;
}


struct flb_ne_collector diskstats_collector = {
    .name = "diskstats",
    .cb_init = ne_diskstats_init,
    .cb_update = ne_diskstats_update,
    .cb_exit = ne_diskstats_exit
};

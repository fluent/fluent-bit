#include <stdio.h>
#include <sys/types.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include "window.h"
#include "throttle.h"

struct throttle_window *window_create(size_t size) {
    struct throttle_window *tw;

    if (size <= 0) {
        return NULL;
    }

    tw = flb_malloc(sizeof(struct throttle_window));

    if (!tw) {
        return NULL;
    }

    tw->size = size;
    tw->total = 0;
    tw->current_timestamp = 0;
    tw->max_index = -1;
    tw->table = flb_calloc(size, sizeof(struct throttle_pane));
    if (!tw->table) {
        flb_error("Could not allocate initial window memory");
        return NULL;
    }

    return tw;
}


int window_get(struct throttle_window *tw, long timestamp) {
    int i;
    for (i=0; i< tw->size; i++ ) {
        if (tw->table[i].timestamp == timestamp) {
            return i;
        }
    }
    return NOT_FOUND;
}
int window_add(struct throttle_window *tw, long timestamp, int val) {
    int i, index, size;
    int sum = 0;
    tw->current_timestamp = timestamp;

    size = tw->size;
    index = window_get(tw, timestamp);

    if (index == NOT_FOUND) {
        if (size - 1 == tw->max_index) {
            /* window must be shifted */
            tw->max_index = -1;
        }
        tw->max_index += 1;
        tw->table[tw->max_index].timestamp= timestamp;
        tw->table[tw->max_index].counter = val;
    } else {
        tw->table[index].counter += val;
    }

    for (i=0; i < tw->size; i++ ) {
        sum += tw->table[i].counter;
        flb_debug("timestamp: %i, value: %i", tw->table[i].timestamp, tw->table[i].counter);
    }
    tw->total = sum;
    flb_debug("total: %i", tw->total);
    return 0;
}

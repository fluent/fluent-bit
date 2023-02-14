// lwrb_dev.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <string.h>
#include "lwrb/lwrb.h"

/* Create data array and buffer */
uint8_t lwrb_data[8 + 1];
lwrb_t buff;

static void debug_buff(uint8_t cmp, size_t r_w, size_t r_r, size_t r_f, size_t r_e);

uint8_t tmp[8];

void
my_buff_evt_fn(lwrb_t* buff, lwrb_evt_type_t type, size_t len) {
    switch (type) {
        case LWRB_EVT_RESET:
            printf("[EVT] Buffer reset event!\r\n");
            break;
        case LWRB_EVT_READ:
            printf("[EVT] Buffer read event: %d byte(s)!\r\n", (int)len);
            break;
        case LWRB_EVT_WRITE:
            printf("[EVT] Buffer write event: %d byte(s)!\r\n", (int)len);
            break;
        default: break;
    }
}

int
main() {
    size_t len;

    /* Init buffer */
    lwrb_init(&buff, lwrb_data, sizeof(lwrb_data));
    lwrb_set_evt_fn(&buff, my_buff_evt_fn);

    lwrb_write(&buff, "abc", 3);
    lwrb_write(&buff, "abc", 3);
    lwrb_write(&buff, "abc", 3);
    len = lwrb_read(&buff, tmp, 9);

    buff.r = 0;
    buff.w = 0;
    memset(lwrb_get_linear_block_write_address(&buff), 'A', lwrb_get_linear_block_write_length(&buff));
    lwrb_advance(&buff, lwrb_get_linear_block_write_length(&buff));

    buff.r = 2;
    buff.w = 0;
    memset(lwrb_get_linear_block_write_address(&buff), 'B', lwrb_get_linear_block_write_length(&buff));
    lwrb_advance(&buff, lwrb_get_linear_block_write_length(&buff));

    buff.r = 3;
    buff.w = 3;
    memset(lwrb_get_linear_block_write_address(&buff), 'C', lwrb_get_linear_block_write_length(&buff));
    lwrb_advance(&buff, lwrb_get_linear_block_write_length(&buff));

    lwrb_reset(&buff);

    //for (size_t r = 0; r < sizeof(lwrb_data); ++r) {
    //    void* ptr;
    //    for (size_t w = 0; w < sizeof(lwrb_data); ++w) {
    //        buff.r = r;
    //        buff.w = w;
    //        ptr = lwrb_get_linear_block_write_address(&buff);
    //        len = lwrb_get_linear_block_write_length(&buff);
    //        printf("W: %3d, R: %3d, LEN: %3d\r\n", (int)w, (int)r, (int)len);
    //    }
    //}

    return 0;
}

static void
debug_buff(uint8_t cmp, size_t r_w, size_t r_r, size_t r_f, size_t r_e) {
    /* Previous and current write, read pointers and full, empty values */
    static size_t p_r, p_w, p_f, p_e;
    size_t r, w, f, e;

    r = buff.r;
    w = buff.w;
    f = lwrb_get_full(&buff);
    e = lwrb_get_free(&buff);

    printf("R: %3d, W: %3d, F: %3d, E: %3d\r\n", (int)r, (int)w, (int)f, (int)e);
}

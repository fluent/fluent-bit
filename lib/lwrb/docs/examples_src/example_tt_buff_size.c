#include "lwrb/lwrb.h"

/* Number of data blocks to write */
#define N          3

/* Create custom data structure */
/* Data is array of 2 32-bit words, 8-bytes */
uint32_t d[2];

/* Create buffer structures */
lwrb_t buff_1;
lwrb_t buff_2;

/* Create data for buffers. Use sizeof structure,
   multiplied by N (for N instances) */
/* Buffer with + 1 bytes bigger memory */
uint8_t buff_data_1[sizeof(d) * N + 1];
/* Buffer without + 1 at the end */
uint8_t buff_data_2[sizeof(d) * N];

/* Write result values */
size_t len_1;
size_t len_2;

/* Initialize buffers */
lwrb_init(&buff_1, buff_data_1, sizeof(buff_data_1));
lwrb_init(&buff_2, buff_data_2, sizeof(buff_data_2));

/* Write data to buffer */
for (size_t i = 0; i < N; ++i) {
    /* Prepare data */
    d.a = i;
    d.b = i * 2;

    /* Write data to both buffers, memory copy from d to buffer */
    len_1 = lwrb_write(&buff_1, d, sizeof(d));
    len_2 = lwrb_write(&buff_2, d, sizeof(d));

    /* Print results */
    printf("Write buffer 1: %d/%d bytes; buffer 2: %d/%d\r\n",
        (int)len_1, (int)sizeof(d),
        (int)len_2, (int)sizeof(d));
}
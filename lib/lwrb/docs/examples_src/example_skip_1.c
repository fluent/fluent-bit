#include "lwrb/lwrb.h"

/* Declare rb instance & raw data */
lwrb_t buff;
uint8_t buff_data[8];

size_t len;
uint8_t* data;

/* Initialize buffer, use buff_data as data array */
lwrb_init(&buff, buff_data, sizeof(buff_data));

/* Use write, read operations, process data */
/* ... */

/* IMAGE PART A */

/* At this stage, we have buffer as on image above */
/* R = 5, W = 4, buffer is considered full */

/* Get length of linear memory at read pointer */
/* Function returns 3 as we can read 3 bytes from buffer in sequence */
/* When function returns 0, there is no memory available in the buffer for read anymore */
if ((len = lwrb_get_linear_block_read_length(&buff)) > 0) {
    /* Get pointer to first element in linear block at read address */
    /* Function returns &buff_data[5] */
    data = lwrb_get_linear_block_read_address(&buff);

    /* Send data via DMA and wait to finish (for sake of example) */
    send_data(data, len);

    /* Now skip sent bytes from buffer = move read pointer */
    lwrb_skip(&buff, len);

    /* Now R points to top of buffer, R = 0 */
    /* At this point, we are at image part B */
}

/* IMAGE PART B */

/* Get length of linear memory at read pointer */
/* Function returns 4 as we can read 4 bytes from buffer in sequence */
/* When function returns 0, there is no memory available in the buffer for read anymore */
if ((len = lwrb_get_linear_block_read_length(&buff)) > 0) {
    /* Get pointer to first element in linear block at read address */
    /* Function returns &buff_data[0] */
    data = lwrb_get_linear_block_read_address(&buff);

    /* Send data via DMA and wait to finish (for sake of example) */
    send_data(data, len);

    /* Now skip sent bytes from buffer = move read pointer */
    /* Read pointer is moved for len bytes */
    lwrb_skip(&buff, len);

    /* Now R points to 4, that is R == W and buffer is now empty */
    /* At this point, we are at image part C */
}

/* IMAGE PART C */

/* Buffer is considered empty as R == W */
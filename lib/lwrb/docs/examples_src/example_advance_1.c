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
/* R = 4, W = 4, buffer is considered empty */

/* Get length of linear memory at write pointer */
/* Function returns 4 as we can write 4 bytes to buffer in sequence */
/* When function returns 0, there is no memory available in the buffer for write anymore */
if ((len = lwrb_get_linear_block_write_length(&buff)) > 0) {
    /* Get pointer to first element in linear block at write address */
    /* Function returns &buff_data[4] */
    data = lwrb_get_linear_block_write_address(&buff);

    /* Receive data via DMA and wait to finish (for sake of example) */
    /* Any other hardware may directly write to data array */
    /* Data array has len bytes length */
    /* Or use memcpy(data, my_array, len); */
    receive_data(data, len);

    /* Now advance buffer for written bytes to buffer = move write pointer */
    /* Write pointer is moved for len bytes */
    lwrb_advance(&buff, len);

    /* Now W points to top of buffer, W = 0 */
    /* At this point, we are at image part B */
}

/* IMAGE PART B */

/* Get length of linear memory at write pointer */
/* Function returns 3 as we can write 3 bytes to buffer in sequence */
/* When function returns 0, there is no memory available in the buffer for write anymore */
if ((len = lwrb_get_linear_block_write_length(&buff)) > 0) {
    /* Get pointer to first element in linear block at write address */
    /* Function returns &buff_data[0] */
    data = lwrb_get_linear_block_write_address(&buff);

    /* Receive data via DMA and wait to finish (for sake of example) */
    /* Any other hardware may directly write to data array */
    /* Data array has len bytes length */
    /* Or use memcpy(data, my_array, len); */
    receive_data(data, len);

    /* Now advance buffer for written bytes to buffer = move write pointer */
    /* Write pointer is moved for len bytes */
    lwrb_advance(&buff, len);

    /* Now W points to 3, R points to 4, that is R == W + 1 and buffer is now full */
    /* At this point, we are at image part C */
}

/* IMAGE PART C */

/* Buffer is considered full as R == W + 1 */
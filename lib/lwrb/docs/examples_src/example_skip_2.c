/* Initialization part skipped */

/* Get length of linear memory at read pointer */
/* When function returns 0, there is no memory
   available in the buffer for read anymore */
while ((len = lwrb_get_linear_block_read_length(&buff)) > 0) {
    /* Get pointer to first element in linear block at read address */
    data = lwrb_get_linear_block_read_address(&buff);

    /* If max length needs to be considered */
    /* simply decrease it and use smaller len on skip function */
    if (len > max_len) {
        len = max_len;
    }

    /* Send data via DMA and wait to finish (for sake of example) */
    send_data(data, len);

    /* Now skip sent bytes from buffer = move read pointer */
    lwrb_skip(&buff, len);
}
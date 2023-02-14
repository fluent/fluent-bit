/* Declare rb instance & raw data */
lwrb_t buff;
uint8_t buff_data[8];

/* Working data length */
volatile size_t len;

/* Send data function */
void send_data(void);

int
main(void) {
    /* Initialize buffer */
    lwrb_init(&buff, buff_data, sizeof(buff_data));

    /* Write 4 bytes of data */
    lwrb_write(&buff, "0123", 4);

    /* Send data over DMA */
    send_data();

    while (1);
}

/* Send data over DMA */
void
send_data(void) {
    /* If len > 0, DMA transfer is on-going */
    if (len > 0) {
        return;
    }

    /* Get maximal length of buffer to read data as linear memory */
    len = lwrb_get_linear_block_read_length(&buff);
    if (len > 0) {
        /* Get pointer to read memory */
        uint8_t* data = lwrb_get_linear_block_read_address(&buff);

        /* Start DMA transfer */
        start_dma_transfer(data, len);
    }

    /* Function does not wait for transfer to finish */
}

/* Interrupt handler */
/* Called on DMA transfer finish */
void
DMA_Interrupt_handler(void) {
    /* Transfer finished */
    if (len > 0) {
        /* Now skip the data (move read pointer) as they were successfully transferred over DMA */
        lwrb_skip(&buff, len);

        /* Reset length = DMA is not active */
        len = 0;

        /* Try to send more */
        send_data();
    }
}

/**
 * \brief           Buffer event function
 */
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

/* Later in the code... */
lwrb_t buff;
uint8_t buff_data[8];

/* Init buffer and set event function */
lwrb_init(&buff, buff_data, sizeof(buff_data));
lwrb_set_evt_fn(&buff, my_buff_evt_fn);

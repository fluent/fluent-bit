/* Declare rb instance & raw data */
lwrb_t buff;
uint8_t buff_data[8];

/* Application variables */
uint8_t data[2];
size_t len;

/* Application code ... */
lwrb_init(&buff, buff_data, sizeof(buff_data)); /* Initialize buffer */

/* Write 4 bytes of data */
lwrb_write(&buff, "0123", 4);

/* Try to read buffer */
/* len holds number of bytes read */
/* Read until len == 0, when buffer is empty */
while ((len = lwrb_read(&buff, data, sizeof(data))) > 0) {
    printf("Successfully read %d bytes\r\n", (int)len);
}
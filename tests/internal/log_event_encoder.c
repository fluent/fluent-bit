
static inline void flb_hex_dump(uint8_t *buffer, size_t buffer_length, size_t line_length) {
    char  *printable_line;
    size_t buffer_index;
    size_t filler_index;

    if (40 < line_length)
    {
        line_length = 40;
    }

    printable_line = alloca(line_length + 1);

    if (NULL == printable_line)
    {
        printf("Alloca returned NULL\n");

        return;
    }

    memset(printable_line, '\0', line_length + 1);

    for (buffer_index = 0 ; buffer_index < buffer_length ; buffer_index++) {
        if (0 != buffer_index &&
            0 == (buffer_index % line_length)) {

            printf("%s\n", printable_line);

            memset(printable_line, '\0', line_length + 1);
        }

        if (0 != isprint(buffer[buffer_index])) {
            printable_line[(buffer_index % line_length)] = buffer[buffer_index];
        }
        else {
            printable_line[(buffer_index % line_length)] = '.';
        }

        printf("%02X ", buffer[buffer_index]);
    }

    if (0 != buffer_index &&
        0 != (buffer_index % line_length)) {

        for (filler_index = 0 ;
             filler_index < (line_length - (buffer_index % line_length)) ;
             filler_index++) {
            printf("   ");
        }

        printf("%s\n", printable_line);

        memset(printable_line, '.', line_length);
    }

}

static int create_sample_map(char *template,
                             char **raw_msgpack_buffer,
                             size_t *raw_msgpack_size,
                             msgpack_object **msgpack_object) {
    int               root_type;
    msgpack_unpacked *unpacked;
    int               result;
    size_t            offset;

    root_type = 0;
    result = flb_pack_json(template,
                           strlen(template),
                           raw_msgpack_buffer,
                           raw_msgpack_size,
                           &root_type,
                           NULL);

    if (result != 0) {
        result = FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE;
    }
    else {
        offset = 0;

        unpacked = flb_calloc(1, sizeof(msgpack_unpacked));

        if (unpacked == NULL) {
            return FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE;
        }

        msgpack_unpacked_init(unpacked);

        result = msgpack_unpack_next(unpacked,
                                     *raw_msgpack_buffer,
                                     *raw_msgpack_size,
                                     &offset);

        if (result != MSGPACK_UNPACK_SUCCESS) {
            result = FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE;
        }
        else {
            *msgpack_object = &unpacked->data;

            result = FLB_EVENT_DECODER_SUCCESS;
        }
    }

    return result;
}


{
    char                        *raw_sample_buffer;
    size_t                       raw_sample_size;
    msgpack_object              *sample_object;

    // struct flb_log_event_encoder encoder;
    int                          result;

    // result = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);

    // if (result != FLB_EVENT_ENCODER_SUCCESS) {
    //     printf("Event encoder initialization error %d\n", result);
    //     exit(0);
    // }

    result = create_sample_map("{\"sample json dict key\": [0,3,0,3,4,5,6]}",
                               &raw_sample_buffer,
                               &raw_sample_size,
                               &sample_object);

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        printf("Sample data creation error %d\n", result);
        exit(0);
    }

    flb_log_event_encoder_record_start(ctx->encoder);
    flb_log_event_encoder_record_timestamp_set(ctx->encoder, &timestamp);

    flb_log_event_encoder_record_metadata_append_string(ctx->encoder, "favorite animal");


    if (0) {
    }
    else if (0) {
        flb_log_event_encoder_record_metadata_append_string(ctx->encoder, "hungry hungry hippo");
    }
    else if (0) {
        flb_log_event_encoder_record_metadata_append_msgpack_raw(ctx->encoder, ctx->ref_metadata_msgpack, ctx->ref_metadata_msgpack_size);
    }
    else if (0) {
        flb_log_event_encoder_record_metadata_set_msgpack_object(ctx->encoder, sample_object);
    }
    else if (0) {
        flb_log_event_encoder_record_metadata_set_msgpack_raw(ctx->encoder, raw_sample_buffer, raw_sample_size);
    }
    else if (1) {
        flb_log_event_encoder_record_metadata_append_msgpack_object(ctx->encoder, sample_object);
    }

    flb_log_event_encoder_record_body_append_string(ctx->encoder, "log");
    flb_log_event_encoder_record_body_append_string(ctx->encoder, "SAMPLE LOG LINE");

    flb_log_event_encoder_record_commit(ctx->encoder);

    // flb_msgpack_dump(ctx->encoder->output_buffer, ctx->encoder->output_length);

    // flb_log_event_encoder_destroy(&encoder);

    // exit(0);
}

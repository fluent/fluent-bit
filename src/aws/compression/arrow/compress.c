/*
 * This converts S3 plugin's request buffer into Apache Arrow format.
 *
 * We use GLib binding to call Arrow functions (which is implemented
 * in C++) from Fluent Bit.
 *
 * https://github.com/apache/arrow/tree/master/c_glib
 */

#include <arrow-glib/arrow-glib.h>
#ifdef FLB_HAVE_ARROW_PARQUET
#include <parquet-glib/parquet-glib.h>
#endif
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <inttypes.h>

/*
 * compression_type_to_garrow - map a generic FLB_AWS_COMPRESS_* codec to the
 * corresponding GArrowCompressionType.
 *
 * This is shared by the Arrow (Feather) and Parquet writers so that
 * compression is treated as an axis applied on top of the format. Codecs that
 * are not valid for a given format are rejected by the caller before reaching
 * the writer; any unmapped value falls back to uncompressed.
 */
static GArrowCompressionType compression_type_to_garrow(int compression_type)
{
        switch (compression_type) {
        case FLB_AWS_COMPRESS_SNAPPY:
            return GARROW_COMPRESSION_TYPE_SNAPPY;
        case FLB_AWS_COMPRESS_GZIP:
            return GARROW_COMPRESSION_TYPE_GZIP;
        case FLB_AWS_COMPRESS_ZSTD:
            return GARROW_COMPRESSION_TYPE_ZSTD;
        default:
            return GARROW_COMPRESSION_TYPE_UNCOMPRESSED;
        }
}

static int choose_block_size(size_t size)
{
    int block_size = 8 * 1024 * 1024;

    while ((size_t) block_size <= size) {
        block_size *= 2;
        if (block_size > 64 * 1024 * 1024) {
            return 64 * 1024 * 1024;
        }
    }

    return block_size;
}

/*
 * GArrowTable is the central structure that represents "table" (a.k.a.
 * data frame).
 */
static GArrowTable* parse_json(uint8_t *json, int size)
{
        GArrowJSONReader *reader;
        GArrowBuffer *buffer;
        GArrowBufferInputStream *input;
        GArrowJSONReadOptions *options;
        GArrowTable *table;
        GError *error = NULL;

        buffer = garrow_buffer_new(json, size);
        if (buffer == NULL) {
            return NULL;
        }

        input = garrow_buffer_input_stream_new(buffer);
        if (input == NULL) {
            g_object_unref(buffer);
            return NULL;
        }

        options = garrow_json_read_options_new();
        if (options == NULL) {
            g_object_unref(buffer);
            g_object_unref(input);
            return NULL;
        }

        g_object_set(options,
                     "block-size", choose_block_size(size),
                     NULL);

        reader = garrow_json_reader_new(GARROW_INPUT_STREAM(input), options, &error);
        if (reader == NULL) {
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(input);
            g_object_unref(options);
            return NULL;
        }

        table = garrow_json_reader_read(reader, &error);
        if (table == NULL) {
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(input);
            g_object_unref(options);
            g_object_unref(reader);
            return NULL;
        }
        g_object_unref(buffer);
        g_object_unref(input);
        g_object_unref(options);
        g_object_unref(reader);
        return table;
}

static GArrowResizableBuffer* table_to_buffer(GArrowTable *table,
                                              int compression_type)
{
        GArrowResizableBuffer *buffer;
        GArrowBufferOutputStream *sink;
        GArrowFeatherWriteProperties *props;
        GError *error = NULL;
        gboolean success;

        buffer = garrow_resizable_buffer_new(0, &error);
        if (buffer == NULL) {
            g_error_free(error);
            return NULL;
        }

        sink = garrow_buffer_output_stream_new(buffer);
        if (sink == NULL) {
            g_object_unref(buffer);
            return NULL;
        }

        /*
         * Apply the requested compression codec on top of the Arrow/Feather
         * format. Arrow IPC only supports ZSTD (and uncompressed); unsupported
         * codecs are rejected at config time before reaching this writer.
         */
        props = garrow_feather_write_properties_new();
        g_object_set(props, "compression",
                     compression_type_to_garrow(compression_type), NULL);

        success = garrow_table_write_as_feather(
                        table, GARROW_OUTPUT_STREAM(sink),
                        props, &error);
        g_object_unref(props);
        if (!success) {
            flb_error("[aws][compress] Failed to write table to arrow "
                      "buffer: %s", error->message);
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            return NULL;
        }
        g_object_unref(sink);
        return buffer;
}

#ifdef FLB_HAVE_ARROW_PARQUET
static GArrowResizableBuffer* table_to_parquet_buffer(GArrowTable *table,
                                                      int compression_type)
{
        GArrowResizableBuffer *buffer;
        GArrowBufferOutputStream *sink;
        GParquetArrowFileWriter *writer;
        GParquetWriterProperties *props;
        GArrowSchema *schema;
        GError *error = NULL;
        gboolean success;
        gint64 n_rows = 0;

        buffer = garrow_resizable_buffer_new(0, &error);
        if (buffer == NULL) {
            g_error_free(error);
            return NULL;
        }

        sink = garrow_buffer_output_stream_new(buffer);
        if (sink == NULL) {
            g_object_unref(buffer);
            return NULL;
        }

        schema = garrow_table_get_schema(table);
        if (schema == NULL) {
            g_object_unref(buffer);
            g_object_unref(sink);
            return NULL;
        }

        props = gparquet_writer_properties_new();
        gparquet_writer_properties_set_compression(
            props, compression_type_to_garrow(compression_type), NULL);

        writer = gparquet_arrow_file_writer_new_arrow(schema,
                                                      GARROW_OUTPUT_STREAM(sink),
                                                      props,
                                                      &error);
        g_object_unref(schema);
        g_object_unref(props);
        if (writer == NULL) {
            flb_error("[aws][compress] Failed to create parquet writer: %s",
                      error->message);
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            return NULL;
        }

        n_rows = garrow_table_get_n_rows(table);

        success = gparquet_arrow_file_writer_write_table(writer, table,
                                                         n_rows, &error);
        if (!success) {
            flb_error("[aws][compress] Failed to write table to parquet "
                      "buffer: %s", error->message);
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            g_object_unref(writer);
            return NULL;
        }

        success = gparquet_arrow_file_writer_close(writer, &error);
        if (!success) {
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            g_object_unref(writer);
            return NULL;
        }

        g_object_unref(sink);
        g_object_unref(writer);
        return buffer;
}
#endif

int out_s3_compress_columnar(int columnar_format, void *json, size_t size,
                             void **out_buf, size_t *out_size,
                             int compression_type)
{
        GArrowTable *table;
        GArrowResizableBuffer *buffer;
        GBytes *bytes;
        gconstpointer ptr;
        gsize len;
        uint8_t *buf;

        table = parse_json((uint8_t *) json, size);
        if (table == NULL) {
            flb_error("[aws][compress] Failed to parse JSON into Arrow Table");
            return -1;
        }

        /* Select the columnar writer; compression is applied on top by each. */
#ifdef FLB_HAVE_ARROW_PARQUET
        if (columnar_format == FLB_AWS_COMPRESS_FORMAT_PARQUET) {
            buffer = table_to_parquet_buffer(table, compression_type);
        }
        else if (columnar_format == FLB_AWS_COMPRESS_FORMAT_ARROW) {
            buffer = table_to_buffer(table, compression_type);
        }
        else {
            flb_error("[aws][compress] unknown columnar format: %d",
                      columnar_format);
            g_object_unref(table);
            return -1;
        }
#else
        if (columnar_format == FLB_AWS_COMPRESS_FORMAT_PARQUET) {
            flb_error("[aws][compress] Parquet format requires parquet-glib "
                      "at compile time");
            g_object_unref(table);
            return -1;
        }
        else if (columnar_format != FLB_AWS_COMPRESS_FORMAT_ARROW) {
            flb_error("[aws][compress] unknown columnar format: %d",
                      columnar_format);
            g_object_unref(table);
            return -1;
        }
        buffer = table_to_buffer(table, compression_type);
#endif
        g_object_unref(table);
        if (buffer == NULL) {
            flb_error("[aws][compress] Failed to encode Arrow Table into "
                      "columnar buffer");
            return -1;
        }

        bytes = garrow_buffer_get_data(GARROW_BUFFER(buffer));
        if (bytes == NULL) {
            g_object_unref(buffer);
            return -1;
        }

        ptr = g_bytes_get_data(bytes, &len);
        if (ptr == NULL) {
            g_object_unref(buffer);
            g_bytes_unref(bytes);
            return -1;
        }

        buf = flb_malloc(len);
        if (buf == NULL) {
            flb_errno();
            g_object_unref(buffer);
            g_bytes_unref(bytes);
            return -1;
        }
        memcpy(buf, ptr, len);
        *out_buf = (void *) buf;
        *out_size = len;

        g_object_unref(buffer);
        g_bytes_unref(bytes);
        return 0;
}

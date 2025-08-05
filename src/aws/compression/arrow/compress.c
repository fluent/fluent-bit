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
#include <inttypes.h>

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

static GArrowResizableBuffer* table_to_buffer(GArrowTable *table)
{
        GArrowResizableBuffer *buffer;
        GArrowBufferOutputStream *sink;
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

        success = garrow_table_write_as_feather(
                        table, GARROW_OUTPUT_STREAM(sink),
                        NULL, &error);
        if (!success) {
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            return NULL;
        }
        g_object_unref(sink);
        return buffer;
}

int out_s3_compress_arrow(void *json, size_t size, void **out_buf, size_t *out_size)
{
        GArrowTable *table;
        GArrowResizableBuffer *buffer;
        GBytes *bytes;
        gconstpointer ptr;
        gsize len;
        uint8_t *buf;

        table = parse_json((uint8_t *) json, size);
        if (table == NULL) {
            return -1;
        }

        buffer = table_to_buffer(table);
        g_object_unref(table);
        if (buffer == NULL) {
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

        buf = malloc(len);
        if (buf == NULL) {
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

#ifdef FLB_HAVE_ARROW_PARQUET
static GArrowResizableBuffer* table_to_parquet_buffer(GArrowTable *table)
{
        GArrowResizableBuffer *buffer;
        GArrowBufferOutputStream *sink;
        GParquetArrowFileWriter *writer;
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

        /* Create a new Parquet file writer */
        writer = gparquet_arrow_file_writer_new_arrow(schema,
                                                      GARROW_OUTPUT_STREAM(sink),
                                                      NULL, /* Arrow writer properties */
                                                      &error);
        g_object_unref(schema);
        if (writer == NULL) {
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            return NULL;
        }

        n_rows = garrow_table_get_n_rows(table);

        /* Write the entire table to the Parquet file buffer */
        success = gparquet_arrow_file_writer_write_table(writer, table, n_rows, &error);
        if (!success) {
            g_error_free(error);
            g_object_unref(buffer);
            g_object_unref(sink);
            g_object_unref(writer);
            return NULL;
        }

        /* Close the writer to finalize the Parquet file metadata */
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


int out_s3_compress_parquet(void *json, size_t size, void **out_buf, size_t *out_size)
{
        GArrowTable *table;
        GArrowResizableBuffer *buffer;
        GBytes *bytes;
        gconstpointer ptr;
        gsize len;
        uint8_t *buf;

        table = parse_json((uint8_t *) json, size);
        if (table == NULL) {
            return -1;
        }

        buffer = table_to_parquet_buffer(table);
        g_object_unref(table);
        if (buffer == NULL) {
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

        buf = malloc(len);
        if (buf == NULL) {
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
#endif

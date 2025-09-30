/*
 * This function converts out_s3 buffer into Apache Arrow format.
 *
 * `json` is a string that contain (concatenated) JSON objects.
 *
 * `size` is the length of the json data (excluding the trailing
 * null-terminator character).
 *
 * Return 0 on success (with `out_buf` and `out_size` updated),
 * and -1 on failure
 */

int out_s3_compress_arrow(void *json, size_t size, void **out_buf, size_t *out_size);

#ifdef FLB_HAVE_ARROW_PARQUET
/*
 * This function converts out_s3 buffer into Apache Parquet format.
 *
 * `json` is a string that contain (concatenated) JSON objects.
 *
 * `size` is the length of the json data (excluding the trailing
 * null-terminator character).
 *
 * Return 0 on success (with `out_buf` and `out_size` updated),
 * and -1 on failure
 */
int out_s3_compress_parquet(void *json, size_t size, void **out_buf, size_t *out_size);
#endif

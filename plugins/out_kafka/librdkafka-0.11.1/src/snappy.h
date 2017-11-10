#ifndef _LINUX_SNAPPY_H
#define _LINUX_SNAPPY_H 1

#include <stdbool.h>
#include <stddef.h>

/* Only needed for compression. This preallocates the worst case */
struct snappy_env {
	unsigned short *hash_table;
	void *scratch;
	void *scratch_output;
};

struct iovec;
int rd_kafka_snappy_init_env(struct snappy_env *env);
int rd_kafka_snappy_init_env_sg(struct snappy_env *env, bool sg);
void rd_kafka_snappy_free_env(struct snappy_env *env);
int rd_kafka_snappy_uncompress_iov(struct iovec *iov_in, int iov_in_len,
			   size_t input_len, char *uncompressed);
int rd_kafka_snappy_uncompress(const char *compressed, size_t n, char *uncompressed);
char *rd_kafka_snappy_java_uncompress (const char *inbuf, size_t inlen,
                                       size_t *outlenp,
                                       char *errstr, size_t errstr_size);
int rd_kafka_snappy_compress_iov(struct snappy_env *env,
                                 const struct iovec *iov_in, size_t iov_in_cnt,
                                 size_t input_length,
                                 struct iovec *iov_out);
bool rd_kafka_snappy_uncompressed_length(const char *buf, size_t len, size_t *result);
size_t rd_kafka_snappy_max_compressed_length(size_t source_len);




#endif

#ifndef _CHUNK_H_
#define _CHUNK_H_

#include <stdint.h>
#include <mk_core/mk_core.h>

/**
 * struct chunk - Contains a chunk of data.
 * @read: Current read position in chunk.
 * @write: Current write position in chunk.
 * @size: Size of container data area.
 * @refs: Refereces held off this chunk.
 *
 * Chunks are used as reference counted flexible sized data containers.
 */
struct chunk {
	struct mk_list _head;

	size_t  read;
	size_t  write;
	size_t  size;
	int32_t refs;

	uint8_t data[0];
};

/**
 * struct chunk_ptr - A pointer to data inside a chunk.
 * @parent: A pointer to chunk.
 * @len: Length of data.
 * @data: Pointer to data inside chunk.
 */
struct chunk_ptr {
	struct chunk *parent;
	size_t   len;
	uint8_t *data;
};

struct chunk_list {
	struct chunk chunks;
};

/**
 * enum chunk_ref_type - Type enum for struct chunk_ref.
 */
enum chunk_ref_type {
	CHUNK_REF_NULL = 0,
	CHUNK_REF_CHUNK,
	CHUNK_REF_UINT8,
};

/**
 * union chunk_ref_union - A data union for struct chunk_ref.
 */
union chunk_ref_union {
	struct chunk *chunk;
	uint8_t *ptr;
};

/**
 * struct chunk_ref - Reference to either to chunk or malloc memory.
 * @t: Type of reference.
 * @u: Data reference.
 */
struct chunk_ref {
	enum chunk_ref_type t;
	union chunk_ref_union u;
};

/**
 * struct chunk_iov - A vector IO container.
 * @index: Index of next unused vector entry.
 * @size: Maximum number of allowed entries.
 */
struct chunk_iov {
	int index;
	int size;

	struct chunk_ref *held_refs;
	struct iovec *io;
};

#define CHUNK_SIZE(SIZE) (SIZE) - offsetof(struct chunk, data)
#define SIZE_CHUNK(SIZE) (SIZE) + offsetof(struct chunk, data)

void chunk_module_init(void *(*mem_alloc_f)(const size_t),
		void *(*mem_realloc_f)(void *, const size_t),
		void (*mem_free_f)(void *));

struct chunk *chunk_new(size_t size);

struct chunk_ptr chunk_read_ptr(struct chunk *c);

struct chunk_ptr chunk_write_ptr(struct chunk *c);

int chunk_set_read_ptr(struct chunk *c, struct chunk_ptr read);

int chunk_set_write_ptr(struct chunk *c, struct chunk_ptr write);

void chunk_free(struct chunk *c);

void chunk_retain(struct chunk *c);

int chunk_release(struct chunk *c);


void chunk_list_init(struct chunk_list *cm);

struct chunk *chunk_list_current(struct chunk_list *cm);

void chunk_list_add(struct chunk_list *cm, struct chunk *a);

void chunk_list_stats(struct chunk_list *cm);

void chunk_list_free_chunks(struct chunk_list *cm);


int chunk_iov_init(struct chunk_iov *iov, int size);

/**
 * chunk_iov_resize - Changes size of iov.
 */
int chunk_iov_resize(struct chunk_iov *iov, int size);

/**
 * chunk_iov_length - Returns total length of iov entries.
 */
size_t chunk_iov_length(struct chunk_iov *iov);

/**
 * chunk_iov_sendv - Writes data in iov to file descriptor.
 */
ssize_t chunk_iov_sendv(int fd, struct chunk_iov *iov);

/**
 * chunk_iov_drop - Drops bytes from front of iovec.
 *
 * Useful with non-blocking IO and partial writes.
 */
int chunk_iov_drop(struct chunk_iov *iov, size_t bytes);

/**
 * chunk_iov_add - Adds chunk entry to chunk_iov.
 *
 * Adds chunk data and creates chunk_ref entry in chunk_iov. Retains
 * chunk_ptr parent.
 */
int chunk_iov_add(struct chunk_iov *iov, struct chunk_ptr cp);

/**
 * chunk_iov_add_ptr - Adds ptr entry to chunk_iov.
 * @do_free: bool, true (1) will free data when done.
 *
 * Adds ptr data and creates chunk_ref.
 */
int chunk_iov_add_ptr(struct chunk_iov *iov,
		void *vptr,
		size_t len,
		int do_free);

/**
 * chunk_iov_reset - Clear iov for reuse.
 *
 * Frees all held references and resets index.
 */
void chunk_iov_reset(struct chunk_iov *iov);

/**
 * chunk_iov_free - Free iov resources.
 */
void chunk_iov_free(struct chunk_iov *iov);

#endif // _CHUNK_H_

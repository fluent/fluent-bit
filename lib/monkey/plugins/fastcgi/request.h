#ifndef _REQUEST_H_
#define _REQUEST_H_

#include "protocol.h"
#include "chunk.h"

/**
 * enum request_state - State of request.
 *
 * REQ_AVAILABLE: Struct is not used by any running request.
 * REQ_ASSIGNED: Struct is assigned to a request and initialized.
 * REQ_SENT: Begin request package has been queued at a fcgi_fd.
 * REQ_STREAM_CLOSED: Response has been received from fcgi_fd.
 * REQ_ENDED: End request package has been received from fcgi_fd.
 * REQ_FINISHED: Response has been sent to client.
 * REQ_FAILED: The request has failed somewhere.
 *
 */
enum request_state {
	REQ_AVAILABLE     = 1,
	REQ_ASSIGNED      = 2,
	REQ_SENT          = 3,
	REQ_STREAM_CLOSED = 4,
	REQ_ENDED         = 5,
	REQ_FINISHED      = 6,
	REQ_FAILED        = 7,
};

/**
 * enum request_flags - Flags on request.
 *
 * REQ_SLEEPING: Request fd event has been put to sleep.
 * REQ_HEADERS_SENT: Request response headers sent.
 */
enum request_flags {
	REQ_SLEEPING = 1,
	REQ_HEADERS_SENT = 2,
};

/**
 * struct request - Request datatype.
 * @state: State of request.
 * @flags: Flags of request.
 *
 * @fd: Client socket.
 * @fcgi_fd: FastCGI server fd.
 *
 * @clock_id: Index of request_list clock.
 *
 * @cs: Client session struct.
 * @sr: Session request struct.
 *
 * @iov: Input and output reference container.
 */
struct request {
	enum request_state state;
	enum request_flags flags;

	int fd;
	int fcgi_fd;

	uint16_t clock_id;

	struct mk_http_session *cs;
	struct mk_http_request *sr;

	struct chunk_iov iov;
};

/**
 * struct req_cache_entry - A cache entry.
 */
struct req_cache_entry {
	struct request *req;
	int fd;
	int fcgi_fd;
	int counter;
};

/* Number of entries in request_cache, must be power of 2. */
#define REQ_CACHE_SIZE 32

/**
 * struct request_cache - Cached entries.
 */
struct request_cache {
	struct req_cache_entry entries[REQ_CACHE_SIZE];
	uint16_t clock_hand;
	uint16_t mask;
};

/**
 * struct request_list - tracks list of requests
 * @n: Number of entries in list.
 * @id_offset: Substracted from req_id to get index in list.
 * @clock_count: Number of clock hands available.
 * @clock_hands: Used with _next_ function to implement round robin.
 *
 * A request list may contain up to UINT16_T entries as that's the
 * maximum number of entries possible to send in a fastcgi header.
 */
struct request_list {
	struct request_cache cache;
	uint16_t size;
	uint16_t id_offset;
	uint16_t clock_count;
	uint16_t *clock_hands;
	struct request *rs;
};

uint16_t next_power_of_2(uint16_t v);

uint16_t is_power_of_2(uint16_t v);

void request_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

int request_init(struct request *preq, int iov_n);

int request_set_state(struct request *req, enum request_state state);

int request_set_flag(struct request *req, enum request_flags flag);

int request_unset_flag(struct request *req, enum request_flags flag);

int request_get_flag(const struct request *req, enum request_flags flag);

int request_assign(struct request *req,
	int fd,
	uint16_t clock_id,
	struct mk_http_session *cs,
	struct mk_http_request *sr);

void request_set_fcgi_fd(struct request *req, int fcgi_fd);

int request_recycle(struct request *req);

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp);

void request_free(struct request *req);


int request_list_init(struct request_list *rl,
		uint16_t clock_count,
		uint16_t id_offset,
		uint16_t size);

/*
 * Gets next available request, starting from rl->clock_hand.
 *
 * Returns NULL on failure, otherwise pointer to struct request.
 */
struct request *request_list_next_available(struct request_list *rl,
		uint16_t clock_id);

/*
 * Gets next assigned request, starting from .clock_hand. The clock_hand
 * will then be set to index of found request.
 *
 * Returns NULL on failure, otherwise pointer to struct request.
 */
struct request *request_list_next_assigned(struct request_list *rl,
		uint16_t clock_id);

struct request *request_list_get_by_fd(struct request_list *rl, int fd);

struct request *request_list_get_by_fcgi_fd(struct request_list *rl, int fd);

struct request *request_list_get(struct request_list *rl, uint16_t req_id);

uint16_t request_list_index_of(struct request_list *rl, struct request *r);

void request_list_free(struct request_list *rl);

#endif // _REQUEST_H_

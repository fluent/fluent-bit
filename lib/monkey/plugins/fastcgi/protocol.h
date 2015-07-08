#ifndef _FCGI_PROTOCOL_H_
#define _FCGI_PROTOCOL_H_

#include <stdint.h>
#include <mk_core/mk_core.h>

#define FCGI_MAX_LENGTH 0xffff
#define FCGI_VERSION_1 1

#define FCGI_HEADER_LEN 8
#define FCGI_BEGIN_BODY_LEN 8
#define FCGI_END_BODY_LEN 8

#define FCGI_MSG_TYPE_STR(type) \
	((type) < 11 ? fcgi_msg_type_str[(type)] : fcgi_msg_type_str[11])

#define FCGI_ROLE_STR(role) \
	((role) < 4 ? fcgi_role_str[(type)] : "UNKNOWN_ROLE")

#define FCGI_PROTOCOL_STATUS_STR(status) \
	((status) < 4 ? fcgi_protocol_status_str[(status)] : fcgi_protocol_status_str[3])

enum fcgi_msg_type {
	FCGI_BEGIN_REQUEST	= 1,
	FCGI_ABORT_REQUEST	= 2,
	FCGI_END_REQUEST	= 3,
	FCGI_PARAMS		= 4,
	FCGI_STDIN              = 5,
	FCGI_STDOUT             = 6,
	FCGI_STDERR             = 7,
	FCGI_DATA               = 8,
	FCGI_GET_VALUES         = 9,
	FCGI_GET_VALUES_RESULT	= 10,
	FCGI_UNKNOWN_TYPE	= 11,
};

enum fcgi_role {
	FCGI_RESPONDER  = 1,
	FCGI_AUTHORIZER = 2,
	FCGI_FILTER     = 3,
};

enum fcgi_flags {
	FCGI_KEEP_CONN = 1,
};

enum fcgi_protocol_status {
	FCGI_REQUEST_COMPLETE = 0,
	FCGI_CANT_MPX_CONN    = 1,
	FCGI_OVERLOADED       = 2,
	FCGI_UNKNOWN_ROLE     = 3,
};

struct fcgi_header {
	uint8_t  version;
	uint8_t  type;
	uint16_t req_id;
	uint16_t body_len;
	uint8_t  body_pad;
	uint8_t reserved[1];
};

struct fcgi_begin_req_body {
	uint16_t role;
	uint8_t  flags;
	uint8_t reserved[5];
};

struct fcgi_end_req_body {
	uint32_t app_status;
	uint8_t  protocol_status;
	uint8_t  reserved[3];
};

struct fcgi_param_entry {
	uint32_t key_len;
	uint32_t value_len;

	size_t position;
	size_t base_len;
	uint8_t *base;
};

extern const char *fcgi_msg_type_str[];

extern const char *fcgi_role_str[];

extern const char *fcgi_protocol_status_str[];

int
fcgi_validate_struct_sizes(void);

size_t
fcgi_read_header(uint8_t *p, struct fcgi_header *h);

size_t
fcgi_write_header(uint8_t *p, const struct fcgi_header *h);

size_t
fcgi_read_end_req_body(uint8_t *p, struct fcgi_end_req_body *b);

size_t
fcgi_write_begin_req_body(uint8_t *p, const struct fcgi_begin_req_body *b);

size_t
fcgi_param_write(uint8_t *p,
	mk_ptr_t key,
	mk_ptr_t value);

/**
 * fcgi_param_entry_init(3) - Setup an entry from buffer.
 */
void fcgi_param_entry_init(struct fcgi_param_entry *e,
		uint8_t *p,
		size_t p_len);

/**
 * fcgi_param_entry_reset(1) - Resets position of entry.
 */
void fcgi_param_entry_reset(struct fcgi_param_entry *e);

/**
 * fcgi_param_entry_next(1) - Point entry at next key value pair.
 *
 * Returns -1 when at end of buffer, 0 otherwise.
 */
int fcgi_param_entry_next(struct fcgi_param_entry *e);

/**
 * fcgi_param_entry_search(2) - Search for key in buffer.
 *
 * Searches from entry position and forward for entry with matching key.
 */
int fcgi_param_entry_search(struct fcgi_param_entry *e, mk_ptr_t key);

/**
 * fcgi_param_entry_key(1) - Returns current key.
 */
mk_ptr_t fcgi_param_entry_key(struct fcgi_param_entry *e);

/**
 * fcgi_param_entry_value(1) - Returns current value.
 */
mk_ptr_t fcgi_param_entry_value(struct fcgi_param_entry *e);

#endif // _FCGI_PROTOCOL_H_

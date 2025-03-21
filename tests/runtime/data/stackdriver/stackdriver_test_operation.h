#define OPERATION_COMMON_CASE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/operation\": "		\
        "{"            \
            "\"id\": \"test_id\","          \
            "\"producer\": \"test_producer\","      \
            "\"first\": true,"      \
            "\"last\": true"       \
        "}"     \
	"}]"

#define EMPTY_OPERATION	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/operation\": "		\
        "{"            \
        "}"     \
	"}]"

#define OPERATION_IN_STRING "["		\
	"1591111124,"			\
	"{"				\
    "\"logging.googleapis.com/operation\": \"some string\""		\
	"}]"

#define PARTIAL_SUBFIELDS	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/operation\": "		\
        "{"            \
            "\"first\": false,"      \
            "\"last\": false"       \
        "}"     \
	"}]"

#define SUBFIELDS_IN_INCORRECT_TYPE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/operation\": "		\
        "{"            \
            "\"id\": 123,"          \
            "\"producer\": true,"      \
            "\"first\": \"some string\","      \
            "\"last\": 123"       \
        "}"     \
	"}]"

#define EXTRA_SUBFIELDS_EXISTED	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/operation\": "		\
        "{"            \
            "\"id\": \"test_id\","          \
            "\"producer\": \"test_producer\","      \
            "\"first\": true,"      \
            "\"last\": true,"       \
            "\"extra_key1\": \"extra_val1\","          \
            "\"extra_key2\": 123,"      \
            "\"extra_key3\": true"          \
        "}"     \
	"}]"

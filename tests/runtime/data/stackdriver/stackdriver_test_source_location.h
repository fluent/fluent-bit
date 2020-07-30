#define SOURCELOCATION_COMMON_CASE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
            "\"file\": \"test_file\","          \
            "\"line\": 123,"      \
            "\"function\": \"test_function\""      \
        "}"     \
	"}]"

#define SOURCELOCATION_COMMON_CASE_LINE_IN_STRING	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
            "\"file\": \"test_file\","          \
            "\"line\": \"123\","      \
            "\"function\": \"test_function\""      \
        "}"     \
	"}]"

#define EMPTY_SOURCELOCATION	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
        "}"     \
	"}]"

#define SOURCELOCATION_IN_STRING "["		\
	"1591111124,"			\
	"{"				\
    "\"logging.googleapis.com/sourceLocation\": \"some string\""		\
	"}]"

#define PARTIAL_SOURCELOCATION	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
            "\"function\": \"test_function\""   \
        "}"     \
	"}]"

#define SOURCELOCATION_SUBFIELDS_IN_INCORRECT_TYPE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
            "\"file\": 123,"          \
            "\"line\": \"some string\","      \
            "\"function\": true"      \
        "}"     \
	"}]"

#define SOURCELOCATION_EXTRA_SUBFIELDS_EXISTED	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
            "\"file\": \"test_file\","          \
            "\"line\": 123,"      \
            "\"function\": \"test_function\","      \
            "\"extra_key1\": \"extra_val1\","          \
            "\"extra_key2\": 123,"      \
            "\"extra_key3\": true"          \
        "}"     \
	"}]"
    
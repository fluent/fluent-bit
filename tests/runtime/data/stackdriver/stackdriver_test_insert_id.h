
#define INSERTID_COMMON_CASE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/insertId\": \"test_insertId\" "		\
	"}]"

#define EMPTY_INSERTID	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/insertId\": \"\" "		\
	"}]"

#define INSERTID_INCORRECT_TYPE_INT	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/insertId\": 123 "		\
	"}]"

#define INSERTID_INCORRECT_TYPE_MAP	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/insertId\": "		\
        "{"           \
        "}"     \
	"}]"

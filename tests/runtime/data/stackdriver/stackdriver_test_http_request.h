#define HTTPREQUEST_COMMON_CASE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"requestMethod\": \"test_requestMethod\","          \
            "\"requestUrl\": \"test_requestUrl\","      \
            "\"userAgent\": \"test_userAgent\","      \
            "\"remoteIp\": \"test_remoteIp\","          \
            "\"serverIp\": \"test_serverIp\","      \
            "\"referer\": \"test_referer\","          \
            "\"latency\": \"0s\","      \
            "\"protocol\": \"test_protocol\","      \
            "\"requestSize\": 123,"          \
            "\"responseSize\": 123,"      \
            "\"status\": 200,"      \
            "\"cacheFillBytes\": 123,"          \
            "\"cacheLookup\": true,"      \
            "\"cacheHit\": true,"      \
            "\"cacheValidatedWithOriginServer\": true"      \
        "}"     \
	"}]"

#define EMPTY_HTTPREQUEST	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
        "}"     \
	"}]"

#define HTTPREQUEST_IN_STRING "["		\
	"1591111124,"			\
	"{"				\
    "\"logging.googleapis.com/http_request\": \"some string\""		\
	"}]"

#define PARTIAL_HTTPREQUEST	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"cacheLookup\": true,"      \
            "\"cacheHit\": true,"      \
            "\"cacheValidatedWithOriginServer\": true"      \
        "}"     \
	"}]"

#define HTTPREQUEST_SUBFIELDS_IN_INCORRECT_TYPE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"requestMethod\": 123,"          \
            "\"requestUrl\": 123,"      \
            "\"userAgent\": 123,"      \
            "\"remoteIp\": 123,"          \
            "\"serverIp\": true,"      \
            "\"referer\": true,"          \
            "\"latency\": false,"      \
            "\"protocol\": false,"      \
            "\"requestSize\": \"some string\","          \
            "\"responseSize\": true,"      \
            "\"status\": false,"      \
            "\"cacheFillBytes\": false,"          \
            "\"cacheLookup\": \"some string\","      \
            "\"cacheHit\": 123,"      \
            "\"cacheValidatedWithOriginServer\": 123"      \
        "}"     \
	"}]"

#define HTTPREQUEST_EXTRA_SUBFIELDS_EXISTED	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"requestMethod\": \"test_requestMethod\","          \
            "\"requestUrl\": \"test_requestUrl\","      \
            "\"userAgent\": \"test_userAgent\","      \
            "\"remoteIp\": \"test_remoteIp\","          \
            "\"serverIp\": \"test_serverIp\","      \
            "\"referer\": \"test_referer\","          \
            "\"latency\": \"0s\","      \
            "\"protocol\": \"test_protocol\","      \
            "\"requestSize\": 123,"          \
            "\"responseSize\": 123,"      \
            "\"status\": 200,"      \
            "\"cacheFillBytes\": 123,"          \
            "\"cacheLookup\": true,"      \
            "\"cacheHit\": true,"      \
            "\"cacheValidatedWithOriginServer\": true,"      \
            "\"extra_key1\": \"extra_val1\","          \
            "\"extra_key2\": 123,"      \
            "\"extra_key3\": true"          \
        "}"     \
	"}]"


/* Tests for 'latency' */
#define HTTPREQUEST_LATENCY_COMMON_CASE	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"latency\": \"  100.00  s  \""      \
        "}"     \
	"}]"

#define HTTPREQUEST_LATENCY_INVALID_SPACES	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"latency\": \"  100. 00  s  \""      \
        "}"     \
	"}]"

#define HTTPREQUEST_LATENCY_INVALID_STRING	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"latency\": \"  s100.00  s  \""      \
        "}"     \
	"}]"

#define HTTPREQUEST_LATENCY_INVALID_END	"["		\
	"1591111124,"			\
	"{"				\
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"latency\": \"  100.00    \""      \
        "}"     \
	"}]"

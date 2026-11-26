/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#define DEFAULT_LABELS	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/labels\": "		\
        "{"            \
            "\"testA\": \"valA\","          \
            "\"testB\": \"valB\""      \
        "}"     \
	"}]"

#define CUSTOM_LABELS	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/customlabels\": "		\
        "{"            \
            "\"testA\": \"valA\","          \
            "\"testB\": \"valB\""      \
        "}"     \
	"}]"

#define DEFAULT_LABELS_K8S_RESOURCE_TYPE	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/local_resource_id\": \"k8s_container.testnamespace.testpod.testctr\","		\
        "\"logging.googleapis.com/labels\": "		\
        "{"            \
            "\"testA\": \"valA\","          \
            "\"testB\": \"valB\""      \
        "}"     \
	"}]"

#define CUSTOM_LABELS_K8S_RESOURCE_TYPE	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/local_resource_id\": \"k8s_container.testnamespace.testpod.testctr\","		\
        "\"logging.googleapis.com/customlabels\": "		\
        "{"            \
            "\"testA\": \"valA\","          \
            "\"testB\": \"valB\""      \
        "}"     \
	"}]"

/* labels value is a string instead of a map - should cause record to be dropped */
#define LABELS_NOT_A_MAP	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/labels\": \"not_a_map\""		\
	"}]"

/* custom labels key with string value instead of map */
#define LABELS_NOT_A_MAP_CUSTOM_KEY	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/customlabels\": \"not_a_map\""	\
	"}]"

/* invalid labels record with extracted fields (httpRequest, operation, */
/* sourceLocation, trace, spanId) to verify cleanup on skip path */
#define LABELS_NOT_A_MAP_WITH_FIELDS	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/labels\": \"not_a_map\","	\
        "\"logging.googleapis.com/trace\": \"test_trace\","	\
        "\"logging.googleapis.com/spanId\": \"test_span\","	\
        "\"logging.googleapis.com/operation\": "		\
        "{"            \
            "\"id\": \"test_id\","          \
            "\"producer\": \"test_producer\","      \
            "\"first\": true,"      \
            "\"last\": true"      \
        "},"     \
        "\"logging.googleapis.com/sourceLocation\": "		\
        "{"            \
            "\"file\": \"test_file\","          \
            "\"line\": 123,"      \
            "\"function\": \"test_function\""      \
        "},"     \
        "\"logging.googleapis.com/http_request\": "		\
        "{"            \
            "\"requestMethod\": \"GET\","          \
            "\"requestUrl\": \"https://example.com\","      \
            "\"status\": 200"      \
        "}"     \
	"}]"

/* two-record batch: first record has invalid labels, second is valid */
#define BATCH_FIRST_RECORD_LABELS_NOT_A_MAP	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/labels\": \"not_a_map\","	\
        "\"message\": \"bad first record\""		\
	"}]"

#define BATCH_FIRST_RECORD_VALID	"["		\
	"1591649196,"			\
	"{"				\
        "\"message\": \"valid second record\""		\
	"}]"

/* all records have invalid labels */
#define BATCH_ALL_LABELS_NOT_A_MAP_1	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/labels\": \"not_a_map\","	\
        "\"message\": \"bad record 1\""		\
	"}]"

#define BATCH_ALL_LABELS_NOT_A_MAP_2	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/labels\": 12345,"	\
        "\"message\": \"bad record 2\""		\
	"}]"


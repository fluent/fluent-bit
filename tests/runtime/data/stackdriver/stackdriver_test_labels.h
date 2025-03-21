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


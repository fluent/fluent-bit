/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#define MONITORED_RESOURCE_COMMON_CASE	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/monitored_resource\": "		\
        "{"            \
            "\"labels\": "        \
            "{"               \
                "\"project_id\": \"monitored_resource_project_id\","          \
                "\"location\": \"monitored_resource_location\","          \
                "\"testA\": \"valA\""      \
            "}"       \
        "}"     \
	"}]"

#define MONITORED_RESOURCE_PRIORITY_HIGHER_THAN_LOCAL_RESOURCE_ID	"["		\
	"1591649196,"			\
	"{"				\
        "\"logging.googleapis.com/monitored_resource\": "		\
        "{"            \
            "\"labels\": "        \
            "{"               \
                "\"project_id\": \"monitored_resource_project_id\","          \
                "\"location\": \"monitored_resource_location\","          \
                "\"cluster_name\": \"monitored_resource_cluster_name\","          \
                "\"namespace_name\": \"monitored_resource_namespace_name\","          \
                "\"pod_name\": \"monitored_resource_pod_name\","          \
                "\"container_name\": \"monitored_resource_container_name\""          \
            "}"       \
        "},"     \
        "\"logging.googleapis.com/local_resource_id\": \"k8s_container.testnamespace.testpod.testctr\""		\
	"}]"

#define MONITORED_RESOURCE_PRIORITY_HIGHER_THAN_GCE_INSTANCE	"["		\
	"1448403340,"                               \
	"{"				\
        "\"logging.googleapis.com/monitored_resource\": "		\
        "{"            \
            "\"labels\": "        \
            "{"               \
                "\"project_id\": \"monitored_resource_project_id\","          \
                "\"zone\": \"monitored_resource_zone\","          \
                "\"instance_id\": \"monitored_resource_instance_id\""          \
            "}"       \
        "}"     \
	"}]"

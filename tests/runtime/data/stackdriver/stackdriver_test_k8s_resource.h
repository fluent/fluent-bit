/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* k8s_container */
#define K8S_CONTAINER_COMMON	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_CONTAINER_COMMON\","		\
    "\"logging.googleapis.com/local_resource_id\": \"k8s_container.testnamespace.testpod.testctr\""		\
	"}]"

#define K8S_CONTAINER_COMMON_DIFF_TAGS	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_CONTAINER_COMMON\","		\
    "\"logging.googleapis.com/local_resource_id\": \"k8s_container.diffnamespace.diffpod.diffctr\""		\
	"}]"

#define K8S_CONTAINER_NO_LOCAL_RESOURCE_ID	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_CONTAINER_COMMON_NO_LOCAL_RESOURCE_ID\""		\
	"}]"

/* k8s_node */
#define K8S_NODE_COMMON	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_NODE_COMMON\","		\
    "\"logging.googleapis.com/local_resource_id\": \"k8s_node.testnode\","		\
	"\"PRIORITY\": 6,"		\
	"\"SYSLOG_FACILITY\": 3,"		\
	"\"_CAP_EFFECTIVE\": \"3fffffffff\","		\
	"\"_PID\": 1387,"		\
	"\"_SYSTEMD_UNIT\": \"docker.service\","		\
	"\"END_KEY\": \"JSON_END\""		\
	"}]"

#define K8S_NODE_NO_LOCAL_RESOURCE_ID	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_NODE_NO_LOCAL_RESOURCE_ID\","		\
	"\"PRIORITY\": 6,"		\
	"\"SYSLOG_FACILITY\": 3,"		\
	"\"_CAP_EFFECTIVE\": \"3fffffffff\","		\
	"\"_PID\": 1387,"		\
	"\"_SYSTEMD_UNIT\": \"docker.service\","		\
	"\"END_KEY\": \"JSON_END\""		\
	"}]"

#define K8S_NODE_LOCAL_RESOURCE_ID_WITH_DOT	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_NODE_LOCAL_RESOURCE_ID_WITH_DOT\","		\
    "\"logging.googleapis.com/local_resource_id\": \"k8s_node.testnode.withdot.dot\","		\
	"\"PRIORITY\": 6,"		\
	"\"SYSLOG_FACILITY\": 3,"		\
	"\"_CAP_EFFECTIVE\": \"3fffffffff\","		\
	"\"_PID\": 1387,"		\
	"\"_SYSTEMD_UNIT\": \"docker.service\","		\
	"\"END_KEY\": \"JSON_END\""		\
	"}]"

/* k8s_pod */
#define K8S_POD_COMMON	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_POD_COMMON\","		\
    "\"logging.googleapis.com/local_resource_id\": \"k8s_pod.testnamespace.testpod\","		\
	"\"key_0\": false,"		\
	"\"key_1\": true,"		\
	"\"key_2\": \"some string\","		\
	"\"key_3\": 0.12345678,"		\
	"\"key_4\": 5000,"		\
	"\"END_KEY\": \"JSON_END\""		\
	"}]"
    
#define K8S_POD_NO_LOCAL_RESOURCE_ID	"["		\
	"1591649196,"			\
	"{"				\
    "\"message\": \"K8S_POD_NO_LOCAL_RESOURCE_ID\","		\
	"\"key_0\": false,"		\
	"\"key_1\": true,"		\
	"\"key_2\": \"some string\","		\
	"\"key_3\": 0.12345678,"		\
	"\"key_4\": 5000,"		\
	"\"END_KEY\": \"JSON_END\""		\
	"}]"

	
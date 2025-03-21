#define LOG_NAME_OVERRIDE	"[" \
	"1591111124," \
	"{"	\
        "\"custom_log_name_key\": \"custom_log_name\"" \
	"}]"

#define LOG_NAME_NO_OVERRIDE	"[" \
	"1591111124," \
	"{"	\
	"}]"

#define LOG_NAME_PROJECT_ID_OVERRIDE "[" \
	"1591111124," \
	"{"	\
		"\"test_project_key\": \"fluent-bit-test-project-2\"" \
	"}]"

#define LOG_NAME_PROJECT_ID_NO_OVERRIDE	"[" \
	"1591111124," \
	"{"	\
	    "\"logging.googleapis.com/projectId\": \"fluent-bit-test-project-2\"" \
	"}]"

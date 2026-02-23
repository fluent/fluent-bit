#define STRING_TEXT_PAYLOAD "[" \
        "1595349600," \
        "{" \
        "\"message\": \"The application errored out\"," \
        "\"logging.googleapis.com/severity\": \"ERROR\"" \
        "}]"

#define STRING_TEXT_PAYLOAD_WITH_RESIDUAL_FIELDS "[" \
        "1595349600," \
        "{" \
        "\"message\": \"The application errored out\"," \
        "\"logging.googleapis.com/severity\": \"ERROR\"," \
        "\"errorCode\": \"400\"" \
        "}]"

#define NON_SCALAR_PAYLOAD_WITH_RESIDUAL_FIELDS "[" \
        "1595349600," \
        "{" \
        "\"message\": " \
        "{"            \
            "\"application_name\": \"my_application\"," \
            "\"error_message\": \"The application errored out\"," \
        "}," \
        "\"logging.googleapis.com/severity\": \"ERROR\"," \
        "\"errorCode\": \"400\"" \
        "}]"

/* Duplicate-key payloads to simulate invalid JSON records from applications. */
#define DUPLICATE_LABELS_WITH_MESSAGE "[" \
        "1595349600," \
        "{" \
        "\"message\": \"raw_message_payload\"," \
        "\"logging.googleapis.com/severity\": \"ERROR\"," \
        "\"logging.googleapis.com/labels\": \"invalid_labels\"," \
        "\"logging.googleapis.com/labels\": 2" \
        "}]"

#define DUPLICATE_LABELS_WITH_LOG "[" \
        "1595349600," \
        "{" \
        "\"log\": \"raw_log_payload\"," \
        "\"logging.googleapis.com/severity\": \"ERROR\"," \
        "\"logging.googleapis.com/labels\": \"invalid_labels\"," \
        "\"logging.googleapis.com/labels\": 2" \
        "}]"

#define DUPLICATE_LABELS_WITH_CUSTOM_TEXT_KEY "[" \
        "1595349600," \
        "{" \
        "\"message\": \"default_message_payload\"," \
        "\"raw_message\": \"custom_text_payload\"," \
        "\"logging.googleapis.com/severity\": \"ERROR\"," \
        "\"logging.googleapis.com/labels\": \"invalid_labels\"," \
        "\"logging.googleapis.com/labels\": 2" \
        "}]"

#define DUPLICATE_LABELS_WITH_NON_SCALAR_TEXT_SOURCES "[" \
        "1595349600," \
        "{" \
        "\"message\": {\"nested\": \"value\"}," \
        "\"log\": {\"inner\": \"value\"}," \
        "\"errorCode\": \"500\"," \
        "\"logging.googleapis.com/severity\": \"ERROR\"," \
        "\"logging.googleapis.com/labels\": \"invalid_labels\"," \
        "\"logging.googleapis.com/labels\": 2" \
        "}]"

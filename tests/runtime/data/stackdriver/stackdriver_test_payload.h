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

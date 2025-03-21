/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#define ONE_FIELD	"["     \
	"1591649196,"			\
	"{"				\
        "\"keyA\": \"valA\""      \
	"}]"

#define MULTIPLE_FIELDS "["     \
    "1591649196,"			\
    "{"            \
        "\"keyA\": \"valA\","          \
        "\"keyB\": \"valB\""      \
    "}]"

#define NESTED_FIELDS	"["     \
	"1591649196,"			\
	"{"				\
        "\"toplevel\": "		\
        "{"            \
            "\"keyA\": \"valA\","          \
            "\"keyB\": \"valB\""      \
        "}"     \
	"}]"

#define LAYERED_NESTED_FIELDS	"["     \
	"1591649196,"			\
	"{"				\
        "\"toplevel\": "		\
        "{"            \
            "\"midlevel\": "		\
            "{"            \
                "\"keyA\": \"valA\""          \
            "},"     \
            "\"keyB\": \"valB\""      \
        "}"     \
	"}]"

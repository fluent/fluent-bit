/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#define NDJSON_BULK "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }\n"                                    \
  "{ \"field1\" : \"value1\" }\n"                                                                                     \
  "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }\n"                                                     \
  "{ \"create\" : { \"_index\" : \"test\", \"_id\" : \"3\" } }\n"                                                     \
  "{ \"field1\" : \"value3\", \"field2\" : \"value4\" }\n"                                                            \
  "{ \"update\" : {\"_id\" : \"1\", \"_index\" : \"test\"} }\n"                                                       \
  "{ \"doc\" : {\"field2\" : \"value2\"} }\n"                                                                         \
  "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"10\" } }\n"                                                     \
  "{ \"field1\" : \"value1\", \"a\": \"line\", \"that\" : \"is\", \"long\": \"line\", \"contained\": \"request\" }\n" \
  "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"20\" } }\n"                                                    \
  "{ \"create\" : { \"_index\" : \"test\", \"_id\" : \"30\" } }\n"                                                    \
  "{ \"field10\" : \"value30\", \"field20\" : \"value40\", \"message\": \"ok\" }\n"                                   \
  "{ \"update\" : {\"_id\" : \"10\", \"_index\" : \"test\"} }\n"                                                      \
  "{ \"doc\" : {\"field20\" : \"value20\"} }\n"                                                                       \
  "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"11\" } }\n"                                                     \
  "{ \"field11\" : \"value11\", \"nested\": {\"message\":\"ok\"} }\n"                                                 \
  "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"21\" } }\n"                                                    \
  "{ \"create\" : { \"_index\" : \"test\", \"_id\" : \"31\" } }\n"                                                    \
  "{ \"field11\" : \"value31\", \"field21\" : \"value41\", \"nested\": { \"multiply\": {\"message\": \"ok\"}} }\n"    \
  "{ \"update\" : {\"_id\" : \"11\", \"_index\" : \"test\"} }\n"                                                      \
  "{ \"doc\" : {\"field21\" : \"value21\"} }\n"                                                                       \
  "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"41\" } }\n"                                                     \
  "{ \"field41\" : \"value41\", \"nested\": {\"message\": \"ok\"} }\n"

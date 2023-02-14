set(src_multiline
  # built-in parsers
  multiline/flb_ml_parser_cri.c
  multiline/flb_ml_parser_docker.c
  multiline/flb_ml_parser_python.c
  multiline/flb_ml_parser_java.c
  multiline/flb_ml_parser_go.c
  multiline/flb_ml_parser_ruby.c
  # core
  multiline/flb_ml_stream.c
  multiline/flb_ml_parser.c
  multiline/flb_ml_group.c
  multiline/flb_ml_rule.c
  multiline/flb_ml.c PARENT_SCOPE
  )

set(src
    otel_envelope.c)

FLB_PLUGIN(processor_opentelemetry_envelope "${src}" "")

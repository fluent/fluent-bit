if(FLB_RECORD_ACCESSOR)
    set(src
        lookup.c)

    FLB_PLUGIN(filter_lookup "${src}" "")
else()
    message(STATUS "Skipping filter_lookup plugin because flb_record_accessor is disabled")
endif()

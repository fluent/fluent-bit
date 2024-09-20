set(src
  in_ebpf.c
)

FLB_PLUGIN(in_ebpf "${src}" "")
target_link_libraries(flb-plugin-in_ebpf -lbpf -lelf -lz)
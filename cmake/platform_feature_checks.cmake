# Feature tests for various platform and compiler capabilities,
# system headers, etc.

include(CheckIncludeFile)
CHECK_INCLUDE_FILE("sys/wait.h" FLB_HAVE_SYS_WAIT_H)
if (FLB_HAVE_SYS_WAIT_H)
    FLB_DEFINITION(FLB_HAVE_SYS_WAIT_H)
endif()

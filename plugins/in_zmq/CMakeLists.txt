if (FLB_IN_ZMQ)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(CZMQ libczmq)
  if (NOT CZMQ_FOUND)
    message(FATAL_ERROR "Could not find libczmq libraries (need libczmq-dev package)")
  else (NOT CZMQ_FOUND)
    message(STATUS "Found libczmq libraries")
  endif (NOT CZMQ_FOUND)
endif (FLB_IN_ZMQ)

set(src
  in_zmq.c)

FLB_PLUGIN(in_zmq "${src}" "${CZMQ_LIBRARIES}")

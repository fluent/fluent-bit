set(src
  in_http.c)

FLB_PLUGIN(in_http "${src}" "")
target_link_libraries(flb-plugin-in_http
  monkey-core-static
  ${CMAKE_DL_LIBS})

# Configuration files
# ===================
# Default values for conf/in_http.conf

set(MK_CONF_LISTEN       "8080")
set(MK_CONF_WORKERS      "1")
set(MK_CONF_TIMEOUT      "15")
set(MK_CONF_INDEXFILE    "index.html index.htm index.php")
set(MK_CONF_HIDEVERSION  "Off")
set(MK_CONF_RESUME       "On")
set(MK_CONF_KA           "On")
set(MK_CONF_KA_TIMEOUT   "5")
set(MK_CONF_KA_MAXREQ    "1000")
set(MK_CONF_REQ_SIZE     "32")
set(MK_CONF_SYMLINK      "Off")
set(MK_CONF_TRANSPORT    "liana")
set(MK_CONF_DEFAULT_MIME "text/plain")
set(MK_CONF_FDT          "On")
set(MK_CONF_OVERCAPACITY "Resist")

# Virtual Host
# ============
set(MK_VH_SERVERNAME     "127.0.0.1")
set(MK_PATH_WWW          "${PROJECT_SOURCE_DIR}/lib/monkey/htdocs")
set(IN_HTTP_CONF_PATH    "${PROJECT_BINARY_DIR}/conf/")

configure_file(
  "in_http_info.h.in"
  "${PROJECT_SOURCE_DIR}/plugins/in_http/in_http_info.h"
  )

configure_file(
  "conf/in_http.conf.in"
  "${PROJECT_BINARY_DIR}/conf/in_http.conf"
  )

configure_file(
  "conf/sites/default.in"
  "${PROJECT_BINARY_DIR}/conf/sites/default"
  )

configure_file(
  "conf/mimetypes.conf.in"
  "${PROJECT_BINARY_DIR}/conf/mimetypes.conf"
  )

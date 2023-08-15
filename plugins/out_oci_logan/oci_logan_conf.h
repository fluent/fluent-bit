

#ifndef FLB_OUT_OCI_LOGAN_CONF_H
#define FLB_OUT_OCI_LOGAN_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>

#include "oci_logan.h"

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                          struct flb_config *config);
int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx);

#endif

/* Fluent Bit - Copyright (C) 2015-2026 The Fluent Bit Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef FLB_VIVO_OTLP_H
#define FLB_VIVO_OTLP_H

#include "vivo.h"
#include <cmetrics/cmetrics.h>

flb_sds_t vivo_otlp_chunk(struct flb_input_instance *source, struct flb_event_chunk *chunk);
flb_sds_t vivo_otlp_metrics(struct cmt *metrics);

#endif

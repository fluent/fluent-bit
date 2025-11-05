#ifndef KUBERNETES_AWS_H
#define KUBERNETES_AWS_H

#include "kube_conf.h"

int fetch_pod_service_map(struct flb_kube *ctx, char *api_server_url, pthread_mutex_t *mutex);
int determine_platform(struct flb_kube *ctx);
void get_cluster_from_environment(struct flb_kube *ctx, struct flb_kube_meta *meta);

#endif

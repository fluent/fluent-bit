/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/tls/flb_tls.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <msgpack.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_property.h"
#include "kubernetes_aws.h"
#include "fluent-bit/flb_ra_key.h"

#define FLB_KUBE_META_CONTAINER_STATUSES_KEY "containerStatuses"
#define FLB_KUBE_META_CONTAINER_STATUSES_KEY_LEN \
    (sizeof(FLB_KUBE_META_CONTAINER_STATUSES_KEY) - 1)
#define FLB_KUBE_META_INIT_CONTAINER_STATUSES_KEY "initContainerStatuses"
#define FLB_KUBE_META_INIT_CONTAINER_STATUSES_KEY_LEN \
    (sizeof(FLB_KUBE_META_INIT_CONTAINER_STATUSES_KEY) - 1)

static void expose_k8s_meta(struct flb_kube *ctx)
{
    char *tmp;
    struct flb_env *env;

    env = ctx->config->env;

    flb_env_set(env, "k8s", "enabled");
    flb_env_set(env, "k8s.namespace", ctx->namespace);
    flb_env_set(env, "k8s.pod_name", ctx->podname);

    tmp = (char *) flb_env_get(env, "NODE_NAME");
    if (tmp) {
        flb_env_set(env, "k8s.node_name", tmp);
    }
}

/* Load local information from a POD context */
static int get_local_pod_info(struct flb_kube *ctx)
{
    int ret;

    ret = flb_kube_client_load_local_pod_info(ctx->kube_client,
                                              &ctx->namespace,
                                              &ctx->namespace_len,
                                              &ctx->podname,
                                              &ctx->podname_len);
    if (ret != FLB_TRUE) {
        flb_plg_warn(ctx->ins, "cannot load local POD info");
        return FLB_FALSE;
    }

    expose_k8s_meta(ctx);
    return FLB_TRUE;
}

/*
 * If a file exists called namespace_podname.meta, load it and use it.
 * If not, fall back to API. This is primarily for diagnostic purposes,
 * e.g. debugging new parsers.
 */
static int get_meta_file_info(struct flb_kube *ctx, const char *namespace,
                              const char *podname, char **buffer, size_t *size,
                              int *root_type) {

    int fd = -1;
    char *payload = NULL;
    size_t payload_size = 0;
    struct stat sb;
    int packed = -1;
    int ret;
    char uri[1024];

    if (ctx->meta_preload_cache_dir && namespace) {

        if (podname && strlen(podname) > 0) {
            ret = snprintf(uri, sizeof(uri) - 1, "%s/%s_%s.meta",
                    ctx->meta_preload_cache_dir, namespace, podname);
        }
        else {
            ret = snprintf(uri, sizeof(uri) - 1, "%s/%s.namespace_meta",
                    ctx->meta_preload_cache_dir, namespace);
        }
        if (ret > 0) {
            fd = open(uri, O_RDONLY, 0);
            if (fd != -1) {
                if (fstat(fd, &sb) == 0) {
                    payload = flb_malloc(sb.st_size);
                    if (!payload) {
                        flb_errno();
                    }
                    else {
                        ret = read(fd, payload, sb.st_size);
                        if (ret == sb.st_size) {
                            payload_size = ret;
                        }
                    }
                }
                close(fd);
            }
        }

        if (payload_size) {
            packed = flb_pack_json(payload, payload_size,
                                   buffer, size, root_type,
                                   NULL);
        }

        if (payload) {
            flb_free(payload);
        }
    }

    return packed;
}

/* Gather pods list information from Kubelet */
static int get_pods_from_kubelet(struct flb_kube *ctx,
                                 const char *namespace, const char *podname,
                                 char **out_buf, size_t *out_size)
{
    int ret;
    int packed = -1;
    int root_type;
    char *buf;
    size_t size;

    *out_buf = NULL;
    *out_size = 0;

    /* used for unit test purposes*/
    packed = get_meta_file_info(ctx, namespace, podname, &buf, &size,
                                &root_type);

    if (packed == -1) {
        flb_plg_debug(ctx->ins,
                      "Send out request to Kubelet for pods information.");
        ret = flb_kube_resource_get_kubelet_pods(ctx->kube_client,
                                                 &buf, &size);
        packed = (ret == 0) ? 0 : -1;
    }

    /* validate pack */
    if (packed == -1) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;

    return 0;
}

/* Gather metadata from API Server */
int get_api_server_configmap(struct flb_kube *ctx,
                               const char *namespace, const char *configmap,
                               char **out_buf, size_t *out_size)
{
    int ret;
    int packed = -1;
    char *buf;
    size_t size;

    *out_buf = NULL;
    *out_size = 0;

    flb_plg_debug(ctx->ins,
                  "Send out request to API Server for configmap information");
    ret = flb_kube_resource_get_configmap(ctx->kube_client, namespace,
                                          configmap, &buf, &size);
    packed = (ret == 0) ? 0 : -1;

    /* validate pack */
    if (packed == -1) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;

    return 0;
}

/* Gather namespace metadata from API Server */
static int get_namespace_api_server_info(struct flb_kube *ctx, const char *namespace,
                               char **out_buf, size_t *out_size)
{
    int ret;
    int packed = -1;
    int root_type;
    char *buf;
    size_t size;

    *out_buf = NULL;
    *out_size = 0;

    /* used for unit test purposes*/
    packed = get_meta_file_info(ctx, namespace, "",
                                &buf, &size, &root_type);

    if (packed == -1) {
        flb_plg_debug(ctx->ins,
                      "Send out request to API Server for namespace information");
        ret = flb_kube_resource_get_namespace(ctx->kube_client, namespace,
                                              &buf, &size);
        packed = (ret == 0) ? 0 : -1;
    }

    /* validate pack */
    if (packed == -1) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;

    return 0;
}

/* Gather pod metadata from API Server */
static int get_pod_api_server_info(struct flb_kube *ctx,
                               const char *namespace, const char *podname,
                               char **out_buf, size_t *out_size)
{
    int ret;
    int packed = -1;
    int root_type;
    char *buf;
    size_t size;

    *out_buf = NULL;
    *out_size = 0;

    /* used for unit test purposes*/
    packed = get_meta_file_info(ctx, namespace, podname,
                                &buf, &size, &root_type);

    if (packed == -1) {
        flb_plg_debug(ctx->ins,
                      "Send out request to API Server for pods information");
        ret = flb_kube_resource_get_pod(ctx->kube_client, namespace, podname,
                                        &buf, &size);
        packed = (ret == 0) ? 0 : -1;
    }

    /* validate pack */
    if (packed == -1) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;

    return 0;
}

static void cb_results(const char *name, const char *value,
                       size_t vlen, void *data)
{
    struct flb_kube_meta *meta = data;

    if (vlen == 0) {
        return;
    }

    if (meta->podname == NULL && strcmp(name, "pod_name") == 0) {
        meta->podname = flb_strndup(value, vlen);
        meta->podname_len = vlen;
        meta->fields++;
    }
    else if (meta->namespace == NULL &&
             strcmp(name, "namespace_name") == 0) {
        meta->namespace = flb_strndup(value, vlen);
        meta->namespace_len = vlen;
        meta->fields++;
    }
    else if (meta->container_name == NULL &&
             strcmp(name, "container_name") == 0) {
        meta->container_name = flb_strndup(value, vlen);
        meta->container_name_len = vlen;
        meta->fields++;
    }
    else if (meta->docker_id == NULL &&
             strcmp(name, "docker_id") == 0) {
        meta->docker_id = flb_strndup(value, vlen);
        meta->docker_id_len = vlen;
        meta->fields++;
    }
    else if (meta->container_hash == NULL &&
             strcmp(name, "container_hash") == 0) {
        meta->container_hash = flb_strndup(value, vlen);
        meta->container_hash_len = vlen;
        meta->fields++;
    }

    return;
}

static int extract_hash(const char * im, int sz, const char ** out, int * outsz)
{
    char * colon = NULL;
    char * slash = NULL;

    *out = NULL;
    *outsz = 0;

    if (sz <= 1) {
        return -1;
    }

    colon = memchr(im, ':', sz);

    if (colon == NULL) {
        return -1;
    } else {
        slash = colon;
        while ((im + sz - slash + 1) > 0 && *(slash + 1) == '/') {
            slash++;
        }
        if (slash == colon) {
            slash = NULL;
        }
    }

    if (slash == NULL && (im + sz - colon) > 0) {
        *out = im;
    }

    if (slash != NULL && (colon - slash) < 0 && (im + sz - slash) > 0) {
        *out = slash + 1;
    }

    if (*out) {
        *outsz = im + sz - *out;
        return 0;
    }
    return -1;
}

/*
 * As per Kubernetes Pod spec,
 * https://kubernetes.io/docs/concepts/workloads/pods/pod/, we look
 * for status.{initContainerStatuses, containerStatuses}.{containerID, imageID, image}
 * where status.{initContainerStatuses, containerStatus}.name == our container
 * name
 * status:
 *   ...
 *   containerStatuses:
 *   - containerID: XXX
 *     image: YYY
 *     imageID: ZZZ
 *     ...
 *     name: nginx-ingress-microk8s
*/
static void extract_container_hash(struct flb_kube_meta *meta,
                                   msgpack_object status)
{
    int i;
    msgpack_object k, v;
    int docker_id_len = 0;
    int container_hash_len = 0;
    int container_image_len = 0;
    const char *container_hash;
    const char *docker_id;
    const char *container_image;
    const char *tmp;
    int tmp_len = 0;
    int name_found = FLB_FALSE;
    /* Process status/containerStatus map for docker_id, container_hash, container_image */
    for (i = 0;
         (meta->docker_id_len == 0 || meta->container_hash_len == 0 ||
          meta->container_image_len == 0) &&
         i < status.via.map.size; i++) {
        k = status.via.map.ptr[i].key;
        if ((k.via.str.size == FLB_KUBE_META_CONTAINER_STATUSES_KEY_LEN &&
             strncmp(k.via.str.ptr,
                     FLB_KUBE_META_CONTAINER_STATUSES_KEY,
                     FLB_KUBE_META_CONTAINER_STATUSES_KEY_LEN) == 0) ||
            (k.via.str.size == FLB_KUBE_META_INIT_CONTAINER_STATUSES_KEY_LEN &&
             strncmp(k.via.str.ptr,
                     FLB_KUBE_META_INIT_CONTAINER_STATUSES_KEY,
                     FLB_KUBE_META_INIT_CONTAINER_STATUSES_KEY_LEN) == 0)) {
            int j;
            v = status.via.map.ptr[i].val;
            for (j = 0;
                 (meta->docker_id_len == 0 ||
                  meta->container_hash_len == 0 ||
                  meta->container_image_len == 0) && j < v.via.array.size;
                 j++) {
                int l;
                msgpack_object k1, k2;
                msgpack_object_str v2;
                k1 = v.via.array.ptr[j];
                for (l = 0;
                     (meta->docker_id_len == 0 ||
                      meta->container_hash_len == 0 ||
                      meta->container_image_len == 0) &&
                     l < k1.via.map.size; l++) {
                    k2 = k1.via.map.ptr[l].key;
                    v2 = k1.via.map.ptr[l].val.via.str;
                    if (k2.via.str.size == sizeof("name") - 1 &&
                        !strncmp(k2.via.str.ptr, "name", k2.via.str.size)) {
                        if (v2.size == meta->container_name_len &&
                            !strncmp(v2.ptr,
                                     meta->container_name,
                                     meta->container_name_len)) {
                            name_found = FLB_TRUE;
                        }
                        else {
                            break;
                        }
                    }
                    else if (k2.via.str.size == sizeof("containerID") - 1 &&
                        !strncmp(k2.via.str.ptr,
                                 "containerID",
                                 k2.via.str.size)) {
                        if (extract_hash(v2.ptr, v2.size, &tmp, &tmp_len) == 0) {
                            docker_id = tmp;
                            docker_id_len = tmp_len;
                        }
                    }
                    else if (k2.via.str.size == sizeof("imageID") - 1 &&
                              !strncmp(k2.via.str.ptr,
                                       "imageID",
                                       k2.via.str.size)) {
                        if (extract_hash(v2.ptr, v2.size, &tmp, &tmp_len) == 0) {
                            container_hash = tmp;
                            container_hash_len = tmp_len;
                        }
                    }
                    else if (k2.via.str.size == sizeof("image") - 1 &&
                              !strncmp(k2.via.str.ptr,
                                       "image",
                                       k2.via.str.size)) {
                        container_image = v2.ptr;
                        container_image_len = v2.size;
                    }
                }
                if (name_found) {
                    if (container_hash_len && !meta->container_hash_len) {
                        meta->container_hash_len = container_hash_len;
                        meta->container_hash = flb_strndup(container_hash,
                                                           container_hash_len);
                        meta->fields++;
                    }
                    if (docker_id_len && !meta->docker_id_len) {
                        meta->docker_id_len = docker_id_len;
                        meta->docker_id = flb_strndup(docker_id, docker_id_len);
                        meta->fields++;
                    }
                    if (container_image_len && !meta->container_image_len) {
                        meta->container_image_len = container_image_len;
                        meta->container_image = flb_strndup(container_image, container_image_len);
                        meta->fields++;
                    }
                    return;
                }
            }
        }
    }
}

static void cb_results_workload(const char *name, const char *value,
                                size_t vlen, void *data)
{
    if (name == NULL || value == NULL ||  vlen == 0 || data == NULL) {
        return;
    }

    struct flb_kube_meta *meta = data;

    if (meta->workload == NULL && strcmp(name, "deployment") == 0) {
        meta->workload = flb_strndup(value, vlen);
        meta->workload_len = vlen;
        meta->fields++;
    }
}

/*
 * Search workload based on the following priority
 * where the top is highest priority. This is done
 * to find the owner of the pod which helps with
 * determining the upper-level management of the pod
 * 1. Deployment name
 * 2. StatefulSet name
 * 3. DaemonSet name
 * 4. Job name
 * 5. CronJob name
 * 6. Pod name
 * 7. Container name
 */
static void search_workload(struct flb_kube_meta *meta, struct flb_kube *ctx,
                            msgpack_object map)
{
    int workload_found = FLB_FALSE;
    int regex_found;
    int ret;
    struct flb_record_accessor *ra_name = NULL;
    struct flb_record_accessor *ra_owner_refs = NULL;
    struct flb_record_accessor *ra_kind = NULL;
    struct flb_record_accessor *ra_owner_name = NULL;
    struct flb_ra_value *name_val = NULL;
    struct flb_ra_value *owner_refs_val = NULL;
    struct flb_ra_value *kind_val = NULL;
    struct flb_ra_value *owner_name_val = NULL;
    struct flb_regex_search result;

    ra_name = flb_ra_create("$name", FLB_FALSE);
    ra_owner_refs = flb_ra_create("$ownerReferences[0]", FLB_FALSE);

    if (!ra_name || !ra_owner_refs) {
        goto cleanup;
    }

    name_val = flb_ra_get_value_object(ra_name, map);
    if (!name_val || name_val->type != FLB_RA_STRING ||
        name_val->o.via.str.size != meta->podname_len ||
        strncmp(name_val->o.via.str.ptr, meta->podname, meta->podname_len) != 0) {
        goto cleanup;
    }

    owner_refs_val = flb_ra_get_value_object(ra_owner_refs, map);
    if (!owner_refs_val || owner_refs_val->o.type != MSGPACK_OBJECT_MAP) {
        goto fallback_workload;
    }

    ra_kind = flb_ra_create("$kind", FLB_FALSE);
    ra_owner_name = flb_ra_create("$name", FLB_FALSE);

    if (!ra_kind || !ra_owner_name) {
        goto cleanup;
    }

    kind_val = flb_ra_get_value_object(ra_kind, owner_refs_val->o);
    owner_name_val = flb_ra_get_value_object(ra_owner_name, owner_refs_val->o);

    if (kind_val && owner_name_val &&
        kind_val->type == FLB_RA_STRING && owner_name_val->type == FLB_RA_STRING) {

        if (kind_val->o.via.str.size == 10 &&
            strncmp(kind_val->o.via.str.ptr, "ReplicaSet", 10) == 0) {
            regex_found = flb_regex_do(ctx->deploymentRegex,
                                       owner_name_val->o.via.str.ptr,
                                       owner_name_val->o.via.str.size,
                                       &result);
            if (regex_found > 0) {
                ret = flb_regex_parse(ctx->deploymentRegex, &result,
                                      cb_results_workload, meta);
                if (ret == -1) {
                    goto cleanup;
                }
            }
            else {
                meta->workload = flb_strndup(owner_name_val->o.via.str.ptr,
                                             owner_name_val->o.via.str.size);
                meta->workload_len = owner_name_val->o.via.str.size;
                meta->fields++;
            }
        }
        else {
            meta->workload = flb_strndup(owner_name_val->o.via.str.ptr,
                                         owner_name_val->o.via.str.size);
            meta->workload_len = owner_name_val->o.via.str.size;
            meta->fields++;
        }
        workload_found = FLB_TRUE;
    }

fallback_workload:
    if (!workload_found) {
        if (meta->podname != NULL) {
            meta->workload = flb_strndup(meta->podname, meta->podname_len);
            meta->workload_len = meta->podname_len;
            meta->fields++;
        }
        else if (meta->container_name != NULL) {
            meta->workload = flb_strndup(meta->container_name,
                                         meta->container_name_len);
            meta->workload_len = meta->container_name_len;
            meta->fields++;
        }
    }

cleanup:
    if (ra_name) {
        flb_ra_destroy(ra_name);
    }
    if (ra_owner_refs) {
        flb_ra_destroy(ra_owner_refs);
    }
    if (ra_kind) {
        flb_ra_destroy(ra_kind);
    }
    if (ra_owner_name) {
        flb_ra_destroy(ra_owner_name);
    }
    if (name_val) {
        flb_ra_key_value_destroy(name_val);
    }
    if (owner_refs_val) {
        flb_ra_key_value_destroy(owner_refs_val);
    }
    if (kind_val) {
        flb_ra_key_value_destroy(kind_val);
    }
    if (owner_name_val) {
        flb_ra_key_value_destroy(owner_name_val);
    }
}

static int search_podname_and_namespace(struct flb_kube_meta *meta,
                                        struct flb_kube *ctx,
                                        msgpack_object map)
{
    int i;
    int podname_found = FLB_FALSE;
    int namespace_found = FLB_FALSE;
    int target_podname_found = FLB_FALSE;
    int target_namespace_found = FLB_FALSE;

    msgpack_object k;
    msgpack_object v;

    for (i = 0; (!podname_found || !namespace_found) &&
                 i < map.via.map.size; i++) {

        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;
        if (k.via.str.size == 4 && !strncmp(k.via.str.ptr, "name", 4)) {

            podname_found = FLB_TRUE;
            if (!strncmp(v.via.str.ptr, meta->podname, meta->podname_len)) {
                target_podname_found = FLB_TRUE;
            }

        }
        else if (k.via.str.size == 9 && !strncmp(k.via.str.ptr,
                                                 "namespace", 9)) {

            namespace_found = FLB_TRUE;
            if (!strncmp((char *)v.via.str.ptr,
                          meta->namespace,
                          meta->namespace_len)) {
                target_namespace_found = FLB_TRUE;
            }
        }
    }

    if (!target_podname_found || !target_namespace_found) {
        return -1;
    }

    return 0;
}

static int search_metadata_in_items(struct flb_kube_meta *meta,
                                    struct flb_kube *ctx,
                                    msgpack_object items_array,
                                    msgpack_object *target_item_map)
{
    int i, j;

    int target_found = FLB_FALSE;
    msgpack_object item_info_map;
    msgpack_object k;
    msgpack_object v;

    for (i = 0; !target_found && i < items_array.via.array.size; i++) {

        item_info_map = items_array.via.array.ptr[i];
        if (item_info_map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        for (j = 0; j < item_info_map.via.map.size; j++) {

            k = item_info_map.via.map.ptr[j].key;
            if (k.via.str.size == 8 &&
                !strncmp(k.via.str.ptr, "metadata", 8)) {

                v = item_info_map.via.map.ptr[j].val;
                if (search_podname_and_namespace(meta, ctx, v) == 0) {
                    target_found = FLB_TRUE;
                    *target_item_map = item_info_map;
                    flb_plg_debug(ctx->ins,
                                  "kubelet find pod: %s and ns: %s match",
                                            meta->podname, meta->namespace);
                }
                break;
            }
        }
    }

    if (!target_found) {
        flb_plg_debug(ctx->ins,
                      "kubelet didn't find pod: %s, ns: %s match",
                      meta->podname, meta->namespace);
        return -1;
    }
    return 0;
}

/* At this point map points to the ROOT map, eg:
 *
 * {
 *  "kind": "PodList",
 *  "apiVersion": "v1",
 *  "metadata": {},
 *  "items": [{
 *    "metadata": {
 *      "name": "fluent-bit-rz47v",
 *      "generateName": "fluent-bit-",
 *      "namespace": "kube-system",
 *      "selfLink": "/api/v1/namespaces/kube-system/pods/fluent-bit-rz47v",
 *      ....
 *    }
 *   }]
 *
 */
static int search_item_in_items(struct flb_kube_meta *meta,
                                struct flb_kube *ctx,
                                msgpack_object api_map,
                                msgpack_object *target_item_map)
{

    int i;
    int items_array_found = FLB_FALSE;

    msgpack_object k;
    msgpack_object v;
    msgpack_object items_array;

    for (i = 0; !items_array_found && i < api_map.via.map.size; i++) {

        k = api_map.via.map.ptr[i].key;
        if (k.via.str.size == 5 && !strncmp(k.via.str.ptr, "items", 5)) {

            v = api_map.via.map.ptr[i].val;
            if (v.type == MSGPACK_OBJECT_ARRAY) {
                items_array = v;
                items_array_found = FLB_TRUE;
            }
        }
    }

    int ret = search_metadata_in_items(meta, ctx, items_array,
                                       target_item_map);

    return ret;
}


static int merge_meta_from_tag(struct flb_kube *ctx, struct flb_kube_meta *meta,
                               char **out_buf, size_t *out_size)
{
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_mp_map_header mh;

    /* Initialize output msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    flb_mp_map_header_init(&mh, &mp_pck);

    if (meta->podname != NULL) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "pod_name", 8);
        msgpack_pack_str(&mp_pck, meta->podname_len);
        msgpack_pack_str_body(&mp_pck, meta->podname, meta->podname_len);
    }

    if (meta->namespace != NULL) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
        msgpack_pack_str(&mp_pck, meta->namespace_len);
        msgpack_pack_str_body(&mp_pck, meta->namespace, meta->namespace_len);
    }

    if (meta->container_name != NULL) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "container_name", 14);
        msgpack_pack_str(&mp_pck, meta->container_name_len);
        msgpack_pack_str_body(&mp_pck, meta->container_name,
                              meta->container_name_len);
    }
    if (meta->docker_id != NULL) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "docker_id", 9);
        msgpack_pack_str(&mp_pck, meta->docker_id_len);
        msgpack_pack_str_body(&mp_pck, meta->docker_id,
                              meta->docker_id_len);
    }

    flb_mp_map_header_end(&mh);

    /* Set outgoing msgpack buffer */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static int merge_namespace_meta(struct flb_kube_meta *meta, struct flb_kube *ctx,
                      const char *api_buf, size_t api_size,
                      char **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int map_size = 0;
    int meta_found = FLB_FALSE;
    int have_labels = -1;
    int have_annotations = -1;
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_unpacked api_result;
    msgpack_unpacked meta_result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object meta_val;
    msgpack_object api_map;

    /*
     *
     * - api_buf: metadata associated to namespace coming from the API server.
     *
     * When merging data we aim to add the following keys from the API server:
     *
     * - labels
     * - annotations
     */

    /* Initialize output msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Iterate API server msgpack and lookup specific fields */
    if (api_buf != NULL) {
        msgpack_unpacked_init(&api_result);
        ret = msgpack_unpack_next(&api_result, api_buf, api_size, &off);
        if (ret == MSGPACK_UNPACK_SUCCESS) {
            api_map = api_result.data;

            /* At this point map points to the ROOT map, eg:
             *
             * {
             *  "kind": "Namespace",
             *  "apiVersion": "v1",
             *  "metadata": {
             *    "name": "fluent-bit",
             *    "uid": "6d1e2042-8013-449c-aa93-e7238391c45f",
             *  ....
             * }
             *
             * We are interested in the 'metadata' map value.
             */
            for (i = 0; !meta_found && i < api_map.via.map.size; i++) {
                k = api_map.via.map.ptr[i].key;
                if (k.via.str.size == 8 && !strncmp(k.via.str.ptr, "metadata", 8)) {
                    meta_val = api_map.via.map.ptr[i].val;
                    if (meta_val.type == MSGPACK_OBJECT_MAP) {
                        meta_found = FLB_TRUE;
                    }
                }
            }

            if (meta_found == FLB_TRUE) {
                /* Process metadata map value */
                msgpack_unpacked_init(&meta_result);
                for (i = 0; i < meta_val.via.map.size; i++) {
                    k = meta_val.via.map.ptr[i].key;

                    char *ptr = (char *) k.via.str.ptr;
                    size_t size = k.via.str.size;


                    if (size == 6 && strncmp(ptr, "labels", 6) == 0) {
                        have_labels = i;
                        if (ctx->namespace_labels == FLB_TRUE) {
                            map_size++;
                        }
                    }
                    else if (size == 11 && strncmp(ptr, "annotations", 11) == 0) {
                        have_annotations = i;
                        if (ctx->namespace_annotations == FLB_TRUE) {
                            map_size++;
                        }
                    }

                    if (have_labels >= 0 && have_annotations >= 0) {
                        break;
                    }
                }
            }

        }
    }


    /* Set Map Size */
    map_size += 1; // +1 for the namespace name
    msgpack_pack_map(&mp_pck, map_size);
    if (meta->namespace != NULL) {
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "name", 4);
        msgpack_pack_str(&mp_pck, meta->namespace_len);
        msgpack_pack_str_body(&mp_pck, meta->namespace, meta->namespace_len);
    }

    /* Append API Server content */
    if (have_labels >= 0 && ctx->namespace_labels == FLB_TRUE) {
        k = meta_val.via.map.ptr[have_labels].key;
        v = meta_val.via.map.ptr[have_labels].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_annotations >= 0 && ctx->namespace_annotations == FLB_TRUE) {
        k = meta_val.via.map.ptr[have_annotations].key;
        v = meta_val.via.map.ptr[have_annotations].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (api_buf != NULL) {
        msgpack_unpacked_destroy(&api_result);
        if (meta_found == FLB_TRUE) {
            msgpack_unpacked_destroy(&meta_result);
        }
    }

    /* Set outgoing msgpack buffer */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static int merge_pod_meta(struct flb_kube_meta *meta, struct flb_kube *ctx,
                      const char *api_buf, size_t api_size,
                      char **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int map_size = 0;
    int meta_found = FLB_FALSE;
    int spec_found = FLB_FALSE;
    int status_found = FLB_FALSE;
    int target_found = FLB_TRUE;
    int have_uid = -1;
    int have_labels = -1;
    int have_annotations = -1;
    int have_owner_references = -1;
    int have_nodename = -1;
    int have_podip = -1;
    int pod_service_found = -1;
    size_t off = 0;
    size_t tmp_service_attr_size = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_unpacked api_result;
    msgpack_unpacked meta_result;
    msgpack_object item_result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object meta_val;
    msgpack_object spec_val;
    msgpack_object status_val;
    msgpack_object api_map;
    msgpack_object ann_map;
    struct flb_kube_props props = {0};
    struct service_attributes *tmp_service_attributes = NULL;
    void *tmp_service_attributes_buf = NULL;

    /*
     * - reg_buf: is a msgpack Map containing meta captured using Regex
     *
     * - api_buf: metadata associated to namespace and POD Name coming from
     *            the API server.
     *
     * When merging data we aim to add the following keys from the API server:
     *
     * - pod_id
     * - labels
     * - annotations
     */

    /* Initialize output msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Iterate API server msgpack and lookup specific fields */
    if (api_buf != NULL) {
        msgpack_unpacked_init(&api_result);
        ret = msgpack_unpack_next(&api_result, api_buf, api_size, &off);
        if (ret == MSGPACK_UNPACK_SUCCESS) {

            if (ctx->use_kubelet) {
                ret = search_item_in_items(meta, ctx, api_result.data, &item_result);
                if (ret == -1) {
                    target_found = FLB_FALSE;
                }
                api_map = target_found ? item_result : api_result.data;
            } else  {
                api_map = api_result.data;
            }

            /* At this point map points to the ROOT map, eg:
             *
             * {
             *  "kind": "Pod",
             *  "apiVersion": "v1",
             *  "metadata": {
             *    "name": "fluent-bit-rz47v",
             *    "generateName": "fluent-bit-",
             *    "namespace": "kube-system",
             *    "selfLink": "/api/v1/namespaces/kube-system/pods/fluent-bit-rz47v",
             *  ....
             * }
             *
             * We are interested into the 'metadata' map value.
             * We are also interested in the spec.nodeName.
             * We are also interested in the status.containerStatuses.
             */
            for (i = 0; target_found && !(meta_found && spec_found && status_found) &&
                        i < api_map.via.map.size; i++) {
                k = api_map.via.map.ptr[i].key;
                if (k.via.str.size == 8 && !strncmp(k.via.str.ptr, "metadata", 8)) {
                    meta_val = api_map.via.map.ptr[i].val;
                    if (ctx->aws_use_pod_association) {
                        search_workload(meta, ctx, meta_val);
                    }
                    if (meta_val.type == MSGPACK_OBJECT_MAP) {
                        meta_found = FLB_TRUE;
                    }
                }
                else if (k.via.str.size == 4 && !strncmp(k.via.str.ptr, "spec", 4)) {
                   spec_val = api_map.via.map.ptr[i].val;
                   spec_found = FLB_TRUE;
                }
                else if (k.via.str.size == 6 && !strncmp(k.via.str.ptr, "status", 6)) {
                   status_val = api_map.via.map.ptr[i].val;
                   status_found = FLB_TRUE;
                }
            }

            if (meta_found == FLB_TRUE) {
                /* Process metadata map value */
                msgpack_unpacked_init(&meta_result);
                for (i = 0; i < meta_val.via.map.size; i++) {
                    k = meta_val.via.map.ptr[i].key;

                    char *ptr = (char *) k.via.str.ptr;
                    size_t size = k.via.str.size;

                    if (size == 3 && strncmp(ptr, "uid", 3) == 0) {
                        have_uid = i;
                        map_size++;
                    }
                    else if (size == 6 && strncmp(ptr, "labels", 6) == 0) {
                        have_labels = i;
                        if (ctx->labels == FLB_TRUE) {
                            map_size++;
                        }
                    }
                    else if (size == 11 && strncmp(ptr, "annotations", 11) == 0) {
                        have_annotations = i;
                        if (ctx->annotations == FLB_TRUE) {
                            map_size++;
                        }
                    }
                    else if (size == 15 && strncmp(ptr, "ownerReferences", 15) == 0) {
                        have_owner_references = i;
                        if (ctx->owner_references == FLB_TRUE) {
                            map_size++;
                        }
                    }

                    if (have_uid >= 0 && have_labels >= 0 && have_annotations >= 0 && have_owner_references >= 0) {
                        break;
                    }
                }
            }

            /* Process spec map value for nodeName */
            if (spec_found == FLB_TRUE) {
                for (i = 0; i < spec_val.via.map.size; i++) {
                    k = spec_val.via.map.ptr[i].key;
                    if (k.via.str.size == 8 &&
                        strncmp(k.via.str.ptr, "nodeName", 8) == 0) {
                        have_nodename = i;
                        map_size++;
                        break;
                    }
                }
            }

            /* Process status map value for podIP */
            if (status_found == FLB_TRUE) {
                for (i = 0; i < status_val.via.map.size; i++) {
                    k = status_val.via.map.ptr[i].key;
                    if (k.via.str.size == 5 &&
                        strncmp(k.via.str.ptr, "podIP", 5) == 0) {
                        have_podip = i;
                        map_size++;
                        break;
                    }
                }
            }

            if ((!meta->container_hash || !meta->docker_id || !meta->container_image) && status_found) {
                extract_container_hash(meta, status_val);
            }
        }
    }
    if (ctx->aws_use_pod_association) {
        pod_service_found = flb_hash_table_get(ctx->aws_pod_service_hash_table,
                                 meta->podname, meta->podname_len,
                                 &tmp_service_attributes_buf, &tmp_service_attr_size);
        if (pod_service_found != -1 && tmp_service_attributes_buf != NULL) {
            tmp_service_attributes = (struct service_attributes *) tmp_service_attributes_buf;
            map_size += tmp_service_attributes->fields;
        }
        if (ctx->platform) {
            map_size++;
        }
    }

    /* Set map size: current + pod_id, labels and annotations */
    map_size += meta->fields;

    /* Append Regex fields */
    msgpack_pack_map(&mp_pck, map_size);
    if (meta->podname != NULL) {
        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "pod_name", 8);
        msgpack_pack_str(&mp_pck, meta->podname_len);
        msgpack_pack_str_body(&mp_pck, meta->podname, meta->podname_len);
    }
    if (meta->namespace != NULL) {
        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
        msgpack_pack_str(&mp_pck, meta->namespace_len);
        msgpack_pack_str_body(&mp_pck, meta->namespace, meta->namespace_len);
    }
    if (ctx->aws_use_pod_association) {
        if (pod_service_found != -1 && tmp_service_attributes != NULL) {
            if (tmp_service_attributes->name[0] != '\0') {
                msgpack_pack_str(&mp_pck, 23);
                msgpack_pack_str_body(&mp_pck, "aws_entity_service_name", 23);
                msgpack_pack_str(&mp_pck, tmp_service_attributes->name_len);
                msgpack_pack_str_body(&mp_pck,
                                      tmp_service_attributes->name,
                                      tmp_service_attributes->name_len);
            }
            if (tmp_service_attributes->environment[0] != '\0') {
                msgpack_pack_str(&mp_pck, 22);
                msgpack_pack_str_body(&mp_pck, "aws_entity_environment", 22);
                msgpack_pack_str(&mp_pck, tmp_service_attributes->environment_len);
                msgpack_pack_str_body(&mp_pck,
                                      tmp_service_attributes->environment,
                                      tmp_service_attributes->environment_len);
            }
            if (tmp_service_attributes->name_source[0] != '\0') {
                msgpack_pack_str(&mp_pck, 22);
                msgpack_pack_str_body(&mp_pck, "aws_entity_name_source", 22);
                msgpack_pack_str(&mp_pck, tmp_service_attributes->name_source_len);
                msgpack_pack_str_body(&mp_pck,
                                      tmp_service_attributes->name_source,
                                      tmp_service_attributes->name_source_len);
            }
        }

        if (ctx->platform != NULL) {
            int platform_len = strlen(ctx->platform);
            msgpack_pack_str(&mp_pck, 19);
            msgpack_pack_str_body(&mp_pck, "aws_entity_platform", 19);
            msgpack_pack_str(&mp_pck, platform_len);
            msgpack_pack_str_body(&mp_pck, ctx->platform, platform_len);
        }
        if (meta->cluster != NULL) {
            msgpack_pack_str(&mp_pck, 18);
            msgpack_pack_str_body(&mp_pck, "aws_entity_cluster", 18);
            msgpack_pack_str(&mp_pck, meta->cluster_len);
            msgpack_pack_str_body(&mp_pck, meta->cluster, meta->cluster_len);
        }
        if (meta->workload != NULL) {
            msgpack_pack_str(&mp_pck, 19);
            msgpack_pack_str_body(&mp_pck, "aws_entity_workload", 19);
            msgpack_pack_str(&mp_pck, meta->workload_len);
            msgpack_pack_str_body(&mp_pck, meta->workload, meta->workload_len);
        }
    }

    /* Append API Server content */
    if (have_uid >= 0) {
        v = meta_val.via.map.ptr[have_uid].val;

        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "pod_id", 6);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_labels >= 0 && ctx->labels == FLB_TRUE) {
        k = meta_val.via.map.ptr[have_labels].key;
        v = meta_val.via.map.ptr[have_labels].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_annotations >= 0 && ctx->annotations == FLB_TRUE) {
        k = meta_val.via.map.ptr[have_annotations].key;
        v = meta_val.via.map.ptr[have_annotations].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_owner_references >= 0 && ctx->owner_references == FLB_TRUE) {
        k = meta_val.via.map.ptr[have_owner_references].key;
        v = meta_val.via.map.ptr[have_owner_references].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_nodename >= 0) {
        v = spec_val.via.map.ptr[have_nodename].val;

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "host", 4);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_podip >= 0) {
        v = status_val.via.map.ptr[have_podip].val;

        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "pod_ip", 6);
        msgpack_pack_object(&mp_pck, v);
    }

    if (meta->container_name != NULL) {
        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "container_name", 14);
        msgpack_pack_str(&mp_pck, meta->container_name_len);
        msgpack_pack_str_body(&mp_pck, meta->container_name,
                              meta->container_name_len);
    }
    if (meta->docker_id != NULL) {
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "docker_id", 9);
        msgpack_pack_str(&mp_pck, meta->docker_id_len);
        msgpack_pack_str_body(&mp_pck, meta->docker_id,
                              meta->docker_id_len);
    }
    if (meta->container_hash != NULL) {
        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "container_hash", 14);
        msgpack_pack_str(&mp_pck, meta->container_hash_len);
        msgpack_pack_str_body(&mp_pck, meta->container_hash,
                              meta->container_hash_len);
    }
    if (meta->container_image != NULL) {
        msgpack_pack_str(&mp_pck, 15);
        msgpack_pack_str_body(&mp_pck, "container_image", 15);
        msgpack_pack_str(&mp_pck, meta->container_image_len);
        msgpack_pack_str_body(&mp_pck, meta->container_image,
                              meta->container_image_len);
    }

    /* Process configuration suggested through Annotations */
    if (have_annotations >= 0) {
        ann_map = meta_val.via.map.ptr[have_annotations].val;

        /* Iterate annotations keys and look for 'logging' key */
        if (ann_map.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < ann_map.via.map.size; i++) {
                k = ann_map.via.map.ptr[i].key;
                v = ann_map.via.map.ptr[i].val;

                if (k.via.str.size > 13 && /* >= 'fluentbit.io/' */
                    strncmp(k.via.str.ptr, "fluentbit.io/", 13) == 0) {

                    /* Validate and set the property */
                    flb_kube_prop_set(ctx, meta,
                                      k.via.str.ptr + 13,
                                      k.via.str.size - 13,
                                      v.via.str.ptr,
                                      v.via.str.size,
                                      &props);
                }
            }
        }

        /* Pack Annotation properties */
        void *prop_buf;
        size_t prop_size;
        flb_kube_prop_pack(&props, &prop_buf, &prop_size);
        msgpack_sbuffer_write(&mp_sbuf, prop_buf, prop_size);
        flb_kube_prop_destroy(&props);
        flb_free(prop_buf);
    }

    if (api_buf != NULL) {
        msgpack_unpacked_destroy(&api_result);
        if (meta_found == FLB_TRUE) {
            msgpack_unpacked_destroy(&meta_result);
        }
    }

    /* Set outgoing msgpack buffer */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static inline int parse_regex_tag_data(struct flb_kube *ctx,
                                const char *tag, int tag_len,
                                const char *data, size_t data_size,
                                struct flb_kube_meta *meta)
{
    int i;
    size_t off = 0;
    ssize_t n;
    int kube_tag_len;
    const char *kube_tag_str;
    const char *container = NULL;
    int container_found = FLB_FALSE;
    int container_length = 0;
    struct flb_regex_search result;
    msgpack_unpacked mp_result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object key;
    msgpack_object val;

    /* Journald */
    if (ctx->use_journal == FLB_TRUE) {
        off = 0;
        msgpack_unpacked_init(&mp_result);
        while (msgpack_unpack_next(&mp_result, data, data_size, &off) == MSGPACK_UNPACK_SUCCESS) {
            root = mp_result.data;
            if (root.type != MSGPACK_OBJECT_ARRAY) {
                continue;
            }

            /* Lookup the CONTAINER_NAME key/value */
            map = root.via.array.ptr[1];
            for (i = 0; i < map.via.map.size; i++) {
                key = map.via.map.ptr[i].key;
                if (key.via.str.size != 14) {
                    continue;
                }

                if (strncmp(key.via.str.ptr, "CONTAINER_NAME", 14) == 0) {
                    val = map.via.map.ptr[i].val;
                    container = val.via.str.ptr;
                    container_length = val.via.str.size;
                    container_found = FLB_TRUE;
                    break;
                }
            }

            if (container_found == FLB_TRUE) {
                break;
            }
        }

        if (container_found == FLB_FALSE) {
            msgpack_unpacked_destroy(&mp_result);
            return -1;
        }
        n = flb_regex_do(ctx->regex,
                         container, container_length,
                         &result);
        msgpack_unpacked_destroy(&mp_result);
    }
    else {
        /*
         * Lookup metadata using regular expression. In order to let the
         * regex work we need to know before hand what's the Tag prefix
         * set and make sure the adjustment can be done.
         */
        kube_tag_len = flb_sds_len(ctx->kube_tag_prefix);
        if (kube_tag_len + 1 >= tag_len) {
            flb_plg_error(ctx->ins, "incoming record tag (%s) is shorter "
                          "than kube_tag_prefix value (%s), skip filter",
                          tag, ctx->kube_tag_prefix);
            return -1;
        }
        kube_tag_str = tag + kube_tag_len;
        kube_tag_len = tag_len - kube_tag_len;

        n = flb_regex_do(ctx->regex, kube_tag_str, kube_tag_len, &result);
    }

    if (n <= 0) {
        flb_plg_warn(ctx->ins, "invalid pattern for given tag %s", tag);
        return -1;
    }

    /* Parse the regex results */
    flb_regex_parse(ctx->regex, &result, cb_results, meta);

    return 0;
}

static inline int extract_namespace_meta(struct flb_kube *ctx,
                               const char *tag, int tag_len,
                               const char *data, size_t data_size,
                               struct flb_kube_meta *meta)
{
    ssize_t n;
    size_t off = 0;
    int ret;

    /* Reset meta context */
    memset(meta, '\0', sizeof(struct flb_kube_meta));

    ret = parse_regex_tag_data(ctx, tag, tag_len, data, data_size, meta);
    if( ret != 0 ) {
        return ret;
    }

    /* Compose API server cache key */
    if (meta->namespace) {
        n = meta->namespace_len + 1;
        meta->cache_key = flb_malloc(n);
        if (!meta->cache_key) {
            flb_errno();
            return -1;
        }

        /* Copy namespace */
        memcpy(meta->cache_key, meta->namespace, meta->namespace_len);
        off = meta->namespace_len;

        meta->cache_key[off] = '\0';
        meta->cache_key_len = off;
    }
    else {
        meta->cache_key = NULL;
        meta->cache_key_len = 0;
    }

    return 0;
}

static inline int extract_pod_meta(struct flb_kube *ctx,
                               const char *tag, int tag_len,
                               const char *data, size_t data_size,
                               struct flb_kube_meta *meta)
{
    size_t off = 0;
    size_t tmp_service_attr_size = 0;
    ssize_t n;
    int ret;
    int pod_service_found;
    struct service_attributes *tmp_service_attributes = NULL;
    void *tmp_service_attributes_buf = NULL;

    /* Reset meta context */
    memset(meta, '\0', sizeof(struct flb_kube_meta));

    ret = parse_regex_tag_data(ctx, tag, tag_len, data, data_size, meta);
    if( ret != 0 ) {
        return ret;
    }

    /* Compose API server cache key */
    if (meta->podname && meta->namespace) {
        /* calculate estimated buffer size */
        n = meta->namespace_len + 1 + meta->podname_len + 1;
        if (meta->container_name) {
            n += meta->container_name_len + 1;
        }
        if (ctx->cache_use_docker_id && meta->docker_id) {
            n += meta->docker_id_len + 1;
        }

        pod_service_found = flb_hash_table_get(ctx->aws_pod_service_hash_table,
                                 meta->podname, meta->podname_len,
                                 &tmp_service_attributes_buf, &tmp_service_attr_size);

        if (pod_service_found != -1 && tmp_service_attributes_buf != NULL) {
            tmp_service_attributes = (struct service_attributes *) tmp_service_attributes_buf;
            if (tmp_service_attributes->name[0] != '\0') {
                n += tmp_service_attributes->name_len + 1;
            }
            if (tmp_service_attributes->environment[0] != '\0') {
                n += tmp_service_attributes->environment_len + 1;
            }
            if (tmp_service_attributes->name_source[0] != '\0') {
                n += tmp_service_attributes->name_source_len + 1;
            }
        }

        meta->cache_key = flb_malloc(n);
        if (!meta->cache_key) {
            flb_errno();
            return -1;
        }

        /* Copy namespace */
        memcpy(meta->cache_key, meta->namespace, meta->namespace_len);
        off = meta->namespace_len;

        /* Separator */
        meta->cache_key[off++] = ':';

        /* Copy podname */
        memcpy(meta->cache_key + off, meta->podname, meta->podname_len);
        off += meta->podname_len;

        if (meta->container_name) {
            /* Separator */
            meta->cache_key[off++] = ':';
            memcpy(meta->cache_key + off, meta->container_name, meta->container_name_len);
            off += meta->container_name_len;
        }

        if (ctx->cache_use_docker_id && meta->docker_id) {
            /* Separator */
            meta->cache_key[off++] = ':';
            memcpy(meta->cache_key + off, meta->docker_id, meta->docker_id_len);
            off += meta->docker_id_len;
        }

        if (pod_service_found != -1 && tmp_service_attributes != NULL) {
            if (tmp_service_attributes->name[0] != '\0') {
                meta->cache_key[off++] = ':';
                memcpy(meta->cache_key + off, tmp_service_attributes->name,
                       tmp_service_attributes->name_len);
                off += tmp_service_attributes->name_len;
            }
            if (tmp_service_attributes->environment[0] != '\0') {
                meta->cache_key[off++] = ':';
                memcpy(meta->cache_key + off, tmp_service_attributes->environment,
                       tmp_service_attributes->environment_len);
                off += tmp_service_attributes->environment_len;
            }
            if (tmp_service_attributes->name_source[0] != '\0') {
                meta->cache_key[off++] = ':';
                memcpy(meta->cache_key + off, tmp_service_attributes->name_source,
                       tmp_service_attributes->name_source_len);
                off += tmp_service_attributes->name_source_len;
            }
        }

        meta->cache_key[off] = '\0';
        meta->cache_key_len = off;
    }
    else {
        meta->cache_key = NULL;
        meta->cache_key_len = 0;
    }

    return 0;
}

/*
 * Given a fixed meta data (namespace), get API server information
 * and merge buffers.
 */
static int get_and_merge_namespace_meta(struct flb_kube *ctx, struct flb_kube_meta *meta,
                              char **out_buf, size_t *out_size)
{
    int ret;
    char *api_buf;
    size_t api_size;

    ret = get_namespace_api_server_info(ctx, meta->namespace,
                                        &api_buf, &api_size);
    if (ret == -1) {
        return -1;
    }

    ret = merge_namespace_meta(meta, ctx, api_buf, api_size,
                    out_buf, out_size);

    if (api_buf != NULL) {
        flb_free(api_buf);
    }

    return ret;
}

/*
 * Given a fixed meta data (namespace and podname), get API server information
 * and merge buffers.
 */
static int get_and_merge_pod_meta(struct flb_kube *ctx, struct flb_kube_meta *meta,
                              char **out_buf, size_t *out_size)
{
    int ret;
    char *api_buf;
    size_t api_size;
    if (ctx->aws_use_pod_association) {
        get_cluster_from_environment(ctx, meta);
    }
    if (ctx->use_tag_for_meta) {
        ret = merge_meta_from_tag(ctx, meta, out_buf, out_size);
        return ret;
    }
    else if (ctx->use_kubelet) {
        ret = get_pods_from_kubelet(ctx, meta->namespace, meta->podname,
                                    &api_buf, &api_size);
    }
    else {
        ret = get_pod_api_server_info(ctx, meta->namespace, meta->podname,
                                  &api_buf, &api_size);
    }
    if (ret == -1) {
        return -1;
    }

    ret = merge_pod_meta(meta, ctx,
                     api_buf, api_size,
                     out_buf, out_size);

    if (api_buf != NULL) {
        flb_free(api_buf);
    }

    return ret;
}

/*
 * Work around kubernetes/kubernetes/issues/78479 by waiting
 * for DNS to start up.
 */
static int wait_for_dns(struct flb_kube *ctx)
{
    int i;
    struct addrinfo *res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    for (i = 0; i < ctx->dns_retries; i++) {
        if (getaddrinfo(ctx->api_host, NULL, &hints, &res) == 0) {
            freeaddrinfo(res);
            return 0;
        }
        flb_plg_info(ctx->ins, "host: %s Wait %i secs until DNS starts up (%i/%i)",
                     ctx->api_host, ctx->dns_wait_time, i + 1, ctx->dns_retries);
        sleep(ctx->dns_wait_time);
    }
    return -1;
}

int flb_kube_pod_association_init(struct flb_kube *ctx, struct flb_config *config)
{
    ctx->aws_pod_association_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                                  ctx->aws_pod_association_host_tls_verify,
                                                  ctx->aws_pod_association_host_tls_debug,
                                                  NULL, NULL,
                                                  ctx->aws_pod_association_host_server_ca_file,
                                                  ctx->aws_pod_association_host_client_cert_file,
                                                  ctx->aws_pod_association_host_client_key_file,
                                                  NULL);
    if (!ctx->aws_pod_association_tls) {
        flb_plg_error(ctx->ins, "[kube_meta] could not create TLS config for pod association host");
        return -1;
    }
    ctx->aws_pod_association_upstream = flb_upstream_create(config,
                                                        ctx->aws_pod_association_host,
                                                        ctx->aws_pod_association_port,
                                                        FLB_IO_TLS, ctx->aws_pod_association_tls);
    if (!ctx->aws_pod_association_upstream) {
        flb_plg_error(ctx->ins, "kube network init create pod association upstream failed");
        flb_tls_destroy(ctx->aws_pod_association_tls);
        ctx->aws_pod_association_tls = NULL;
        return -1;
    }
    flb_upstream_thread_safe(ctx->aws_pod_association_upstream);
    return 0;
}

static int flb_kube_network_init(struct flb_kube *ctx, struct flb_config *config)
{
    int ret;
    struct flb_kube_client_config client_config = {0};

    ctx->aws_pod_association_upstream = NULL;
    ctx->aws_pod_association_tls = NULL;

    client_config.api_host = ctx->api_host;
    client_config.api_port = ctx->api_port;
    client_config.api_https = ctx->api_https;
    client_config.kubelet_host = ctx->kubelet_host;
    client_config.kubelet_port = ctx->kubelet_port;
    client_config.kubelet_https = FLB_TRUE;
    client_config.use_kubelet = ctx->use_kubelet;
    client_config.tls_ca_path = ctx->tls_ca_path;
    client_config.tls_ca_file = ctx->tls_ca_file;
    client_config.tls_vhost = ctx->tls_vhost;
    client_config.tls_debug = ctx->tls_debug;
    client_config.tls_verify = ctx->tls_verify;
    client_config.tls_verify_hostname = ctx->tls_verify_hostname;
    client_config.token_file = ctx->token_file;
    client_config.token_command = ctx->kube_token_command;
    client_config.token_ttl = ctx->kube_token_ttl;
    client_config.buffer_size = ctx->buffer_size;

    /* This is for unit test diagnostic purposes. */
    if (ctx->meta_preload_cache_dir) {
        client_config.kubelet_https = FLB_FALSE;
    }

    ctx->kube_client = flb_kube_client_create(config, &client_config);
    if (ctx->kube_client == NULL) {
        flb_plg_debug(ctx->ins, "kube network init create client failed");
        return -1;
    }

    /* Continue the filter kubernetes plugin functionality if the pod_association fails */
    if (ctx->aws_use_pod_association) {
        ret = flb_kube_pod_association_init(ctx, config);
        if (ret == -1) {
            flb_plg_debug(ctx->ins, "pod association network init failed");
        }
    }

    return 0;
}

/* Initialize local context */
int flb_kube_meta_init(struct flb_kube *ctx, struct flb_config *config)
{
    int ret;
    char *meta_buf;
    size_t meta_size;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_plg_warn(ctx->ins, "using Dummy Metadata");
        return 0;
    }

    if (ctx->use_tag_for_meta) {
        flb_plg_info(ctx->ins, "no network access required (OK)");
        return 0;
    }

    /* Init network */
    ret = flb_kube_network_init(ctx, config);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "could not initialize Kubernetes network client");
        return -1;
    }

    /* Gather local info */
    ret = get_local_pod_info(ctx);
    if (ret == FLB_TRUE && !ctx->use_tag_for_meta) {
        flb_plg_info(ctx->ins, "local POD info OK");

        ret = wait_for_dns(ctx);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "could not resolve %s", ctx->api_host);
            return -1;
        }

        if (ctx->use_kubelet) {
            /* Gather info from Kubelet */
            flb_plg_info(ctx->ins, "testing connectivity with Kubelet...");
            ret = get_pods_from_kubelet(ctx, ctx->namespace, ctx->podname,
                                              &meta_buf, &meta_size);
        }
        else {
            /* Gather info from API server */
            flb_plg_info(ctx->ins, "testing connectivity with API server...");
            ret = get_pod_api_server_info(ctx, ctx->namespace, ctx->podname,
                                   &meta_buf, &meta_size);
        }

        if (ret == -1) {
            if (!ctx->podname) {
                flb_plg_warn(ctx->ins, "could not get meta for local POD");
            }
            else {
                flb_plg_warn(ctx->ins, "could not get meta for POD %s",
                         ctx->podname);
            }
            return -1;
        }

        // Using namespace labels/annotations requires a kube api connection (even if Use_Kubelet On)
        if(ctx->namespace_labels == FLB_TRUE || ctx->namespace_annotations == FLB_TRUE) {
            // Ensure we have read access to the namespace the local pod is running under
            flb_plg_info(ctx->ins, "testing connectivity with API server for namespaces...");
            ret = get_namespace_api_server_info(ctx, ctx->namespace, &meta_buf, &meta_size);
        }
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "could not get meta for namespace %s",
                        ctx->namespace);
            return -1;
        }


        ctx->platform = NULL;
        if (ctx->aws_use_pod_association) {
            ret = determine_platform(ctx);
            if (ret == -1) {
                ctx->platform = flb_strdup(NATIVE_KUBERNETES_PLATFORM);
            }
            else {
                ctx->platform = flb_strdup(EKS_PLATFORM);
            }
        }
        flb_plg_info(ctx->ins, "connectivity OK");
        flb_free(meta_buf);
    }
    else {
        flb_plg_info(ctx->ins, "Fluent Bit not running in a POD");
    }

    return 0;
}

int flb_kube_dummy_meta_get(char **out_buf, size_t *out_size)
{
    int len;
    time_t t;
    char stime[32];
    struct tm result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    t = time(NULL);
    localtime_r(&t, &result);
#ifdef FLB_SYSTEM_WINDOWS
    asctime_s(stime, sizeof(stime), &result);
#else
    asctime_r(&result, stime);
#endif
    len = strlen(stime) - 1;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 5 /* dummy */ );
    msgpack_pack_str_body(&mp_pck, "dummy", 5);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, stime, len);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static inline int flb_kube_pod_meta_get(struct flb_kube *ctx,
                      const char *tag, int tag_len,
                      const char *data, size_t data_size,
                      const char **out_buf, size_t *out_size,
                      struct flb_kube_meta *meta,
                      struct flb_kube_props *props)
{
    int id;
    int ret;
    const char *hash_meta_buf;
    char *tmp_hash_meta_buf;
    size_t off = 0;
    size_t hash_meta_size;
    msgpack_unpacked result;

    /* Get metadata from tag or record (cache key is the important one) */
    ret = extract_pod_meta(ctx, tag, tag_len, data, data_size, meta);
    if (ret != 0) {
        return -1;
    }

    /* Check if we have some data associated to the cache key */
    ret = flb_hash_table_get(ctx->hash_table,
                             meta->cache_key, meta->cache_key_len,
                             (void *) &hash_meta_buf, &hash_meta_size);
    if (ret == -1) {
        /* Retrieve API server meta and merge with local meta */
        ret = get_and_merge_pod_meta(ctx, meta,
                                 &tmp_hash_meta_buf, &hash_meta_size);
        if (ret == -1) {
            *out_buf = NULL;
            *out_size = 0;
            return 0;
        }

        id = flb_hash_table_add(ctx->hash_table,
                                meta->cache_key, meta->cache_key_len,
                                tmp_hash_meta_buf, hash_meta_size);
        if (id >= 0) {
            /*
             * Release the original buffer created on extract_pod_meta() as a new
             * copy has been generated into the hash table, then re-set
             * the outgoing buffer and size.
             */
            flb_free(tmp_hash_meta_buf);
            flb_hash_table_get_by_id(ctx->hash_table, id, meta->cache_key,
                                     &hash_meta_buf, &hash_meta_size);
        }
    }

    /*
     * The retrieved buffer may have two serialized items:
     *
     * [0] = kubernetes metadata (annotations, labels)
     * [1] = Annotation properties
     *
     * note: annotation properties are optional.
     */
    msgpack_unpacked_init(&result);

    /* Unpack to get the offset/bytes of the first item */
    msgpack_unpack_next(&result, hash_meta_buf, hash_meta_size, &off);

    /* Set the pointer and proper size for the caller */
    *out_buf = hash_meta_buf;
    *out_size = off;

    /* A new unpack_next() call will succeed If annotation properties exists */
    ret = msgpack_unpack_next(&result, hash_meta_buf, hash_meta_size, &off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        /* Unpack the remaining data into properties structure */
        flb_kube_prop_unpack(props,
                             hash_meta_buf + *out_size,
                             hash_meta_size - *out_size);
    }
    msgpack_unpacked_destroy(&result);

    return 0;
}

static inline int flb_kube_namespace_meta_get(struct flb_kube *ctx,
                      const char *tag, int tag_len,
                      const char *data, size_t data_size,
                      const char **out_buf, size_t *out_size,
                      struct flb_kube_meta *meta)
{
    int id;
    int ret;
    const char *hash_meta_buf;
    char *tmp_hash_meta_buf;
    size_t off = 0;
    size_t hash_meta_size;
    msgpack_unpacked result;

    /* Get metadata from tag or record (cache key is the important one) */
    ret = extract_namespace_meta(ctx, tag, tag_len, data, data_size, meta);
    if (ret != 0) {
        return -1;
    }

    /* Check if we have some data associated to the cache key */
    ret = flb_hash_table_get(ctx->namespace_hash_table,
                             meta->cache_key, meta->cache_key_len,
                             (void *) &hash_meta_buf, &hash_meta_size);
    if (ret == -1) {
        /* Retrieve API server meta and merge with local meta */
        ret = get_and_merge_namespace_meta(ctx, meta,
                                 &tmp_hash_meta_buf, &hash_meta_size);
        if (ret == -1) {
            *out_buf = NULL;
            *out_size = 0;
            return 0;
        }

        id = flb_hash_table_add(ctx->namespace_hash_table,
                                meta->cache_key, meta->cache_key_len,
                                tmp_hash_meta_buf, hash_meta_size);
        if (id >= 0) {
            /*
             * Release the original buffer created on extract_namespace_meta()
             * as a new copy has been generated into the hash table, then reset
             * the outgoing buffer and size.
             */
            flb_free(tmp_hash_meta_buf);
            flb_hash_table_get_by_id(ctx->namespace_hash_table, id, meta->cache_key,
                                     &hash_meta_buf, &hash_meta_size);
        }
    }

    /*
     * The retrieved buffer may have serialized items:
     *
     * [0] = kubernetes metadata (annotations, labels)
     *
     */
    msgpack_unpacked_init(&result);

    /* Unpack to get the offset/bytes of the first item */
    msgpack_unpack_next(&result, hash_meta_buf, hash_meta_size, &off);

    /* Set the pointer and proper size for the caller */
    *out_buf = hash_meta_buf;
    *out_size = off;

    msgpack_unpacked_destroy(&result);

    return 0;
}

int flb_kube_meta_get(struct flb_kube *ctx,
                      const char *tag, int tag_len,
                      const char *data, size_t data_size,
                      const char **out_buf, size_t *out_size,
                      const char **namespace_out_buf,
                      size_t *namespace_out_size,
                      struct flb_kube_meta *meta,
                      struct flb_kube_props *props,
                      struct flb_kube_meta *namespace_meta
                      )
{
    int ret_namespace_meta = -1;
    int ret_pod_meta = -1;

    if(ctx->namespace_labels == FLB_TRUE || ctx->namespace_annotations == FLB_TRUE) {
        ret_namespace_meta = flb_kube_namespace_meta_get(ctx, tag, tag_len, data,
                        data_size, namespace_out_buf, namespace_out_size, namespace_meta);
    }

    if(ctx->namespace_metadata_only == FLB_FALSE) {
        ret_pod_meta = flb_kube_pod_meta_get(ctx, tag, tag_len, data, data_size,
                                             out_buf, out_size, meta, props);
    }

    // If we get metadata from either namespace or pod info, return success
    if( ret_pod_meta == 0 || ret_namespace_meta == 0) {
        return 0;
    }

    return -1;
}

int flb_kube_meta_release(struct flb_kube_meta *meta)
{
    int r = 0;

    if (meta->namespace) {
        flb_free(meta->namespace);
        r++;
    }

    if (meta->podname) {
        flb_free(meta->podname);
        r++;
    }

    if (meta->container_name) {
        flb_free(meta->container_name);
        r++;
    }

    if (meta->docker_id) {
        flb_free(meta->docker_id);
        r++;
    }

    if (meta->container_hash) {
        flb_free(meta->container_hash);
        r++;
    }

    if (meta->container_image) {
        flb_free(meta->container_image);
        r++;
    }

    if (meta->cache_key) {
        flb_free(meta->cache_key);
    }

    if (meta->workload) {
        flb_free(meta->workload);
    }

    if (meta->cluster) {
        flb_free(meta->cluster);
    }

    return r;
}

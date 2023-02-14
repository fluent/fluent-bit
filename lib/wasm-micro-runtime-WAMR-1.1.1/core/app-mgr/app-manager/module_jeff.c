/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifdef ENABLE_JEFF

#include "module_jeff.h"
#include "jeff_export.h"
#include "../vmcore_jeff/jeff-runtime.h"
#include "../vmcore_jeff/jeff-thread.h"
#include "../vmcore_jeff/jeff-buffer.h"
#include "../vmcore_jeff/jeff-tool.h"
#include "../vmcore_jeff/jeff-tool-priv.h"
#include "app_manager-host.h"
#include "bh_queue.h"
#include "attr-container.h"
#include "attr-container-util.h"
#include "bh_thread.h"
#include "ems_gc.h"
#include "coap_ext.h"
#include "libcore.h"
#include "event.h"
#include "watchdog.h"

#define DEFAULT_APPLET_TIMEOUT (3 * 60 * 1000)
#define DEFAULT_APPLET_HEAP_SIZE (48 * 1024)
#define MIN_APPLET_HEAP_SIZE (2 * 1024)
#define MAX_APPLET_HEAP_SIZE (1024 * 1024)

typedef struct jeff_applet_data {
    /* Java Applet Object */
    JeffObjectRef applet_obj;

#if BEIHAI_ENABLE_TOOL_AGENT != 0
    /* Whether the applet is in debug mode */
    bool debug_mode;
    /* Queue of the tool agent */
    bh_queue *tool_agent_queue;
#endif

    /* VM instance */
    JeffInstanceLocalRoot *vm_instance;
    /* Applet Main file */
    JeffFileHeaderLinked *main_file;
    /* Permissions of the Java Applet */
    char *perms;
} jeff_applet_data;

/* Jeff class com.intel.aee.AEEApplet */
static JeffClassHeaderLinked *class_AEEApplet;
/* Jeff class com.intel.aee.Request */
static JeffClassHeaderLinked *class_AEERequest;
/* Jeff class com.intel.aee.Timer */
static JeffClassHeaderLinked *class_Timer;
/* Jeff class com.intel.aee.Sensor */
static JeffClassHeaderLinked *class_Sensor;
/* Jeff class com.intel.aee.ble.BLEManager */
static JeffClassHeaderLinked *class_BLEManager;
/* Jeff class com.intel.aee.ble.BLEDevice */
static JeffClassHeaderLinked *class_BLEDevice;
/* Jeff class com.intel.aee.ble.BLEGattService */
JeffClassHeaderLinked *class_BLEGattService;
/* Jeff class com.intel.aee.ble.BLEGattCharacteristic */
JeffClassHeaderLinked *class_BLEGattCharacteristic;
/* Jeff class com.intel.aee.ble.BLEGattDescriptor */
JeffClassHeaderLinked *class_BLEGattDescriptor;
/* Jeff class com.intel.aee.gpio.GPIOChannel */
static JeffClassHeaderLinked *class_GPIOChannel;
/* Jeff method void com.intel.aee.AEEApplet.onInit() */
static JeffMethodLinked *method_AEEApplet_onInit;
/* Jeff method void com.intel.aee.AEEApplet.onDestroy() */
static JeffMethodLinked *method_AEEApplet_onDestroy;
/* Jeff method void com.intel.aee.AEEApplet.callOnRequest(Request request) */
static JeffMethodLinked *method_AEEApplet_callOnRequest;
/* Jeff method void com.intel.aee.Timer.callOnTimer() */
static JeffMethodLinked *method_callOnTimer;
/* Jeff method void com.intel.aee.Sensor.callOnSensorEvent() */
static JeffMethodLinked *method_callOnSensorEvent;
/* Jeff method void com.intel.aee.ble.BLEManager.callOnBLEStartDiscovery() */
static JeffMethodLinked *method_callOnBLEStartDiscovery;
/* Jeff method void com.intel.aee.ble.BLEManager.callOnBLEConnected() */
static JeffMethodLinked *method_callOnBLEConnected;
/* Jeff method void com.intel.aee.ble.BLEManager.callOnBLEDisonnected() */
static JeffMethodLinked *method_callOnBLEDisconnected;
/* Jeff method void com.intel.aee.ble.BLEManager.callOnBLENotification() */
static JeffMethodLinked *method_callOnBLENotification;
/* Jeff method void com.intel.aee.ble.BLEManager.callOnBLEIndication() */
static JeffMethodLinked *method_callOnBLEIndication;
/* Jeff method void com.intel.aee.ble.BLEManager.callOnBLEPasskeyEntry() */
static JeffMethodLinked *method_callOnBLEPasskeyEntry;
/* Jeff method void com.intel.aee.gpio.GPIOChannel.callOnGPIOInterrupt() */
static JeffMethodLinked *method_callOnGPIOInterrupt;
/* Jeff method void com.intel.aee.ble.BLEManager.getBLEDevice() */
static JeffMethodLinked *method_callOnBLEManagerGetBLEDevice;

static jeff_applet_data *
app_manager_get_jeff_applet_data()
{
    module_data *m_data = app_manager_get_module_data(Module_Jeff);
    return (jeff_applet_data *)m_data->internal_data;
}

#if BEIHAI_ENABLE_TOOL_AGENT != 0
void *
app_manager_get_tool_agent_queue()
{
    return app_manager_get_jeff_applet_data()->tool_agent_queue;
}
#endif

#if BEIHAI_ENABLE_TOOL_AGENT != 0
static bool
is_tool_agent_running(module_data *m_data)
{
    jeff_applet_data *applet_data = (jeff_applet_data *)m_data->internal_data;
    return (applet_data->debug_mode && applet_data->tool_agent_queue
            && applet_data->vm_instance->tool_agent);
}
#endif

static char *
get_class_qname(const JeffString *pname, const JeffString *cname)
{
    unsigned int length =
        pname->length ? pname->length + 2 + cname->length : cname->length + 1;
    char *buf = APP_MGR_MALLOC(length), *p;

    if (!buf)
        return NULL;

    p = buf;
    if (pname->length) {
        bh_memcpy_s(p, pname->length, pname->value, pname->length);
        p += pname->length;
        *p++ = '.';
    }

    bh_memcpy_s(p, cname->length, cname->value, cname->length);
    p += cname->length;
    *p = '\0';

    return buf;
}

static void
send_exception_event_to_host(const char *applet_name, const char *exc_name)
{
    attr_container_t *payload;
    bh_request_msg_t msg;
    char *url;
    int url_len;

    payload = attr_container_create("exception detail");
    if (!payload) {
        app_manager_printf("Send exception to host fail: allocate memory");
        return;
    }

    if (!attr_container_set_string(&payload, "exception name", exc_name)
        || !attr_container_set_string(&payload, "stack trace", "TODO")
        || !attr_container_set_string(&payload, "applet name", applet_name)) {
        app_manager_printf("Send exception to host fail: set attr");
        goto fail;
    }

    url_len = strlen("/exception/") + strlen(applet_name);
    url = APP_MGR_MALLOC(url_len + 1);
    if (!url) {
        app_manager_printf("Send exception to host fail: allocate memory");
        goto fail;
    }
    memset(url, 0, url_len + 1);
    bh_strcpy_s(url, url_len + 1, "/exception/");
    bh_strcat_s(url, url_len + 1, applet_name);

    memset(&msg, 0, sizeof(msg));
    msg.url = url;
    msg.action = COAP_PUT;
    msg.payload = (char *)payload;

    app_send_request_msg_to_host(&msg);

    APP_MGR_FREE(url);

fail:
    attr_container_destroy(payload);
}

static bool
check_exception()
{
    if (jeff_runtime_get_exception()) {
        jeff_printf("V1.Exception thrown when running applet '%s':\n",
                    app_manager_get_module_name(Module_Jeff));
        jeff_runtime_print_exception();
        jeff_printf("\n");
        jeff_printf(NULL);
    }

    if (!app_manager_is_interrupting_module(Module_Jeff)) {
        attr_container_t *payload;
        int payload_len;
        JeffClassHeaderLinked *exc_class =
            jeff_object_class_pointer(jeff_runtime_get_exception());
        char *qname_buf = get_class_qname(jeff_get_class_pname(exc_class),
                                          jeff_get_class_cname(exc_class));

        /* Send exception event to host */
        if (qname_buf) {
            send_exception_event_to_host(
                app_manager_get_module_name(Module_Jeff), qname_buf);
            APP_MGR_FREE(qname_buf);
        }

        /* Uninstall the applet */
        if ((payload = attr_container_create("uninstall myself"))) {
            if (attr_container_set_string(
                    &payload, "name", app_manager_get_module_name(Module_Jeff))
                /* Set special flag to prevent app manager making response
                   since this is an internal message */
                && attr_container_set_bool(&payload, "do not reply me", true)) {
                request_t request = { 0 };
                payload_len = attr_container_get_serialize_length(payload);

                    init_request(request, "/applet", COAP_DELETE, (char *)payload, payload_len));
                    app_mgr_lookup_resource(&request);

                    // TODO: confirm this is right
                    attr_container_destroy(payload);
            }
        }

        jeff_runtime_set_exception(NULL);
        return true;
    }

    return false;
}

static bool
app_manager_initialize_class(JeffClassHeaderLinked *c)
{
    jeff_runtime_initialize_class(c);
    return !check_exception();
}

static bool
app_manager_initialize_object(JeffObjectRef obj)
{
    jeff_runtime_initialize_object(obj);
    return !check_exception();
}

static bool
app_manager_call_java(JeffMethodLinked *method, unsigned int argc,
                      uint32 argv[], uint8 argt[])
{
    module_data *m_data = app_manager_get_module_data(Module_Jeff);
    watchdog_timer *wd_timer = &m_data->wd_timer;
    bool is_wd_started = false;

#if BEIHAI_ENABLE_TOOL_AGENT != 0
    /* Only start watchdog when debugger is not running */
    if (!is_tool_agent_running(m_data)) {
#endif
        watchdog_timer_start(wd_timer);
        is_wd_started = true;
#if BEIHAI_ENABLE_TOOL_AGENT != 0
    }
#endif

    jeff_runtime_call_java(method, argc, argv, argt);

    if (is_wd_started) {
        os_mutex_lock(&wd_timer->lock);
        if (!wd_timer->is_interrupting) {
            wd_timer->is_stopped = true;
            watchdog_timer_stop(wd_timer);
        }
        os_mutex_unlock(&wd_timer->lock);
    }

    return !check_exception();
}

static AEEBLEDevice
create_object_BLEDevice(ble_device_info *dev_info)
{
    JeffLocalObjectRef ref;
    AEEBLEDevice dev_struct;

    jeff_runtime_push_local_object_ref(&ref);

    ref.val = jeff_runtime_new_object(class_BLEDevice);

    if (!ref.val) {
        jeff_runtime_pop_local_object_ref(1);
        return NULL;
    }

    dev_struct = (AEEBLEDevice)(ref.val);
    dev_struct->rssi = dev_info->rssi;
    dev_struct->mac =
        (jbyteArray)jeff_runtime_create_byte_array((int8 *)dev_info->mac, 6);

    app_manager_printf("adv_data_len:%d,scan_response_len:%d\n",
                       dev_info->adv_data_len, dev_info->scan_response_len);

    dev_struct->advData = (jbyteArray)jeff_runtime_create_byte_array(
        (int8 *)dev_info->adv_data, dev_info->adv_data_len);
    dev_struct->scanResponse = (jbyteArray)jeff_runtime_create_byte_array(
        (int8 *)dev_info->scan_response, dev_info->scan_response_len);
    dev_struct->addressType = dev_info->address_type;
    jeff_runtime_initialize_object(ref.val);
    jeff_runtime_pop_local_object_ref(1);
    if ((dev_struct->mac == NULL) || (dev_struct->advData == NULL)
        || (dev_struct->scanResponse == NULL)) {
        return NULL;
    }
    return (AEEBLEDevice)ref.val;
}

static void
app_instance_process_ble_msg(char *msg)
{
    bh_queue_ble_sub_msg_t *ble_msg = (bh_queue_ble_sub_msg_t *)msg;
    unsigned int argv[5];
    uint8 argt[5];

    ble_device_info *dev_info;

    dev_info = (ble_device_info *)ble_msg->payload;
    AEEBLEDevice ble_dev;

    argv[0] = (unsigned int)(jbyteArray)jeff_runtime_create_byte_array(
        (int8 *)dev_info->mac, 6);
    argt[0] = 1;
    if (!app_manager_call_java(method_callOnBLEManagerGetBLEDevice, 1, argv,
                               argt)) {
        app_manager_printf(
            "app_manager_call_java BLEManagerGetBLEDevice fail error\n");
        goto fail;
    }
    ble_dev = (AEEBLEDevice)argv[0];
    if (ble_dev == NULL) {
        ble_dev = create_object_BLEDevice(dev_info);
        if (ble_dev == NULL) {
            goto fail;
        }
    }

    switch (ble_msg->type) {
        case BLE_SUB_EVENT_DISCOVERY:
        {
            argv[0] = (unsigned int)ble_dev;
            argt[0] = 1;
            ble_dev->rssi = dev_info->rssi;
            if (!app_manager_call_java(method_callOnBLEStartDiscovery, 1, argv,
                                       argt)) {
                app_manager_printf(
                    "app_manager_call_java method_callOnBLEStartDiscovery "
                    "fail error\n");
                goto fail;
            }
            break;
        }

        case BLE_SUB_EVENT_CONNECTED:
        {
            if (ble_dev) {
                argv[0] = (unsigned int)ble_dev;
                argv[1] = 0;
                argt[0] = 1;
                argt[1] = 1;
                if (!app_manager_call_java(method_callOnBLEConnected, 2, argv,
                                           argt)) {
                    app_manager_printf(
                        "app_manager_call_java method_callOnBLEConnected "
                        "fail error\n");
                    goto fail;
                }
            }
            break;
        }

        case BLE_SUB_EVENT_DISCONNECTED:
        {
            app_manager_printf("app instance received disconnected\n");

            if (ble_dev) {
                argv[0] = (unsigned int)ble_dev;
                argv[1] = 0;
                argt[0] = 1;
                argt[1] = 1;
                ble_dev->rssi = dev_info->rssi;
                if (!app_manager_call_java(method_callOnBLEDisconnected, 2,
                                           argv, argt)) {
                    app_manager_printf(
                        "app_manager_call_java "
                        "method_callOnBLEDisconnected fail error\n");
                    goto fail;
                }
            }
            break;
        }

        case BLE_SUB_EVENT_NOTIFICATION:
        {
            if (ble_dev) {
                argv[0] = (unsigned int)ble_dev;
                argv[1] =
                    (unsigned int)(jbyteArray)jeff_runtime_create_byte_array(
                        (int8 *)dev_info->private_data,
                        dev_info->private_data_length);
                argv[2] = dev_info->value_handle;
                argv[3] = dev_info->ccc_handle;
                argt[1] = 1;
                argt[2] = 0;
                argt[3] = 0;
                ble_dev->rssi = dev_info->rssi;
                if (!app_manager_call_java(method_callOnBLENotification, 4,
                                           argv, argt)) {
                    app_manager_printf(
                        "app_manager_call_java "
                        "method_callOnBLENotification fail error\n");
                    goto fail;
                }
            }
            break;
        }

        case BLE_SUB_EVENT_INDICATION:
        {
            if (ble_dev) {
                argv[0] = (unsigned int)ble_dev;
                argv[1] =
                    (unsigned int)(jbyteArray)jeff_runtime_create_byte_array(
                        (int8 *)dev_info->private_data,
                        dev_info->private_data_length);
                argv[2] = dev_info->value_handle;
                argv[3] = dev_info->ccc_handle;
                argt[0] = 1;
                argt[1] = 1;
                argt[2] = 0;
                argt[3] = 0;
                ble_dev->rssi = dev_info->rssi;
                if (!app_manager_call_java(method_callOnBLEIndication, 4, argv,
                                           argt)) {
                    app_manager_printf(
                        "app_manager_call_java method_callOnBLEIndication "
                        "fail error\n");
                    goto fail;
                }
            }
            break;
        }

        case BLE_SUB_EVENT_PASSKEYENTRY:
        {

            if (ble_dev) {
                argv[0] = (unsigned int)ble_dev;
                argt[0] = 1;
                argt[1] = 1;
                ble_dev->rssi = dev_info->rssi;
                if (!app_manager_call_java(method_callOnBLEPasskeyEntry, 1,
                                           argv, argt)) {
                    app_manager_printf(
                        "app_manager_call_java "
                        "method_callOnBLEPasskeyEntry fail error\n");
                    goto fail;
                }
            }
            break;
        }

        case BLE_SUB_EVENT_SECURITY_LEVEL_CHANGE:
        {
            if (ble_dev) {
                ble_dev->securityLevel = dev_info->security_level;
            }
            break;
        }

        default:
            break;
    }

fail:
    if (dev_info->scan_response != NULL) {
        APP_MGR_FREE(dev_info->scan_response);
    }
    if (dev_info->private_data != NULL) {
        APP_MGR_FREE(dev_info->private_data);
    }

    if (dev_info->adv_data != NULL) {
        APP_MGR_FREE(dev_info->adv_data);
    }
    if (dev_info != NULL) {
        APP_MGR_FREE(dev_info);
    }
}

static void
app_instance_free_ble_msg(char *msg)
{
    bh_queue_ble_sub_msg_t *ble_msg = (bh_queue_ble_sub_msg_t *)msg;
    ble_device_info *dev_info;

    dev_info = (ble_device_info *)ble_msg->payload;

    if (dev_info->scan_response != NULL)
        APP_MGR_FREE(dev_info->scan_response);

    if (dev_info->private_data != NULL)
        APP_MGR_FREE(dev_info->private_data);

    if (dev_info->adv_data != NULL)
        APP_MGR_FREE(dev_info->adv_data);

    if (dev_info != NULL)
        APP_MGR_FREE(dev_info);
}

static void
app_instance_queue_free_callback(void *queue_msg)
{
    bh_queue_msg_t *msg = (bh_queue_msg_t *)queue_msg;

    switch (msg->message_type) {
        case APPLET_REQUEST:
        {
            bh_request_msg_t *req_msg = (bh_request_msg_t *)msg->payload;
            APP_MGR_FREE(req_msg);
            break;
        }

        case TIMER_EVENT:
        {
            break;
        }

        case SENSOR_EVENT:
        {
            if (msg->payload) {
                bh_sensor_event_t *sensor_event =
                    (bh_sensor_event_t *)msg->payload;
                attr_container_t *event = sensor_event->event;

                attr_container_destroy(event);
                APP_MGR_FREE(sensor_event);
            }
            break;
        }

        case BLE_EVENT:
        {
            if (msg->payload) {
                app_instance_free_ble_msg(msg->payload);
                APP_MGR_FREE(msg->payload);
            }
            break;
        }

        case GPIO_INTERRUPT_EVENT:
        {
            break;
        }

        default:
        {
            break;
        }
    }

    APP_MGR_FREE(msg);
}

static void
app_instance_queue_callback(void *queue_msg)
{
    bh_queue_msg_t *msg = (bh_queue_msg_t *)queue_msg;
    unsigned int argv[5];
    uint8 argt[5];

    if (app_manager_is_interrupting_module(Module_Jeff)) {
        app_instance_queue_free_callback(queue_msg);
        return;
    }

    switch (msg->message_type) {
        case APPLET_REQUEST:
        {
            JeffLocalObjectRef ref;
            AEERequest req_obj;
            bh_request_msg_t *req_msg = (bh_request_msg_t *)msg->payload;
            attr_container_t *attr_cont = (attr_container_t *)req_msg->payload;
            module_data *m_data = app_manager_get_module_data(Module_Jeff);
            jeff_applet_data *applet_data =
                (jeff_applet_data *)m_data->internal_data;

            app_manager_printf("Applet %s got request, url %s, action %d\n",
                               m_data->module_name, req_msg->url,
                               req_msg->action);

            /* Create Request object */
            req_obj =
                (AEERequest)jeff_object_new(m_data->heap, class_AEERequest);
            if (!req_obj) {
                app_manager_printf("Applet process request failed: create "
                                   "request obj failed.\n");
                goto fail1;
            }

            jeff_runtime_push_local_object_ref(&ref);
            ref.val = (JeffObjectRef)req_obj;

            req_obj->mid = req_msg->mid;
            req_obj->action = req_msg->action;
            req_obj->fmt = req_msg->fmt;

            /* Create Java url string */
            if (req_msg->url) {
                req_obj->url =
                    (jstring)jeff_runtime_create_java_string(req_msg->url);
                if (!req_obj->url) {
                    app_manager_printf("Applet process request failed: "
                                       "create url string failed.\n");
                    goto fail2;
                }
            }

            /* Create Java AttributeObject payload */
            if (attr_cont
                && !attr_container_to_attr_obj(attr_cont, &req_obj->payload)) {
                app_manager_printf("Applet process request failed: convert "
                                   "payload failed.\n");
                goto fail2;
            }

            /* Call AEEApplet.callOnRequest(Request request) method  */
            argv[0] = (unsigned int)applet_data->applet_obj;
            argv[1] = (unsigned int)req_obj;
            argt[0] = argt[1] = 1;
            app_manager_call_java(method_AEEApplet_callOnRequest, 2, argv,
                                  argt);
            app_manager_printf("Applet process request success.\n");

        fail2:
            jeff_runtime_pop_local_object_ref(1);
        fail1:
            APP_MGR_FREE(req_msg);
            break;
        }

        case TIMER_EVENT:
        {
            if (msg->payload) {
                /* Call Timer.callOnTimer() method */
                argv[0] = (unsigned int)msg->payload;
                argt[0] = 1;
                app_manager_call_java(method_callOnTimer, 1, argv, argt);
            }
            break;
        }

        case SENSOR_EVENT:
        {
            if (msg->payload) {
                bh_sensor_event_t *sensor_event =
                    (bh_sensor_event_t *)msg->payload;
                AEESensor sensor = sensor_event->sensor;
                attr_container_t *event = sensor_event->event;
                bool ret = attr_container_to_attr_obj(event, &sensor->event);

                attr_container_destroy(event);
                APP_MGR_FREE(sensor_event);

                if (ret) {
                    /* Call Sensor.callOnSensorEvent() method */
                    argv[0] = (unsigned int)sensor;
                    argt[0] = 1;
                    app_manager_call_java(method_callOnSensorEvent, 1, argv,
                                          argt);
                }
            }
            break;
        }

        case BLE_EVENT:
        {
            if (msg->payload) {
                app_instance_process_ble_msg(msg->payload);
                APP_MGR_FREE(msg->payload);
            }
            break;
        }

        case GPIO_INTERRUPT_EVENT:
        {
            AEEGPIOChannel gpio_ch = (AEEGPIOChannel)msg->payload;

            if ((gpio_ch == NULL) || (gpio_ch->callback == 0)
                || (gpio_ch->listener == NULL)) {
                break;
            }
            argv[0] = (unsigned int)gpio_ch;
            argt[0] = 1;
            bool ret_value = app_manager_call_java(method_callOnGPIOInterrupt,
                                                   1, argv, argt);

            if (!ret_value) {
                app_manager_printf(
                    "app_manager_call_java "
                    "method_method_callOnGPIOInterrupt return false\n");
            }
            break;
        }

        default:
        {
            app_manager_printf(
                "Invalid message type of applet queue message.\n");
            break;
        }
    }

    APP_MGR_FREE(msg);
}

static JeffClassHeaderLinked *
find_main_class(JeffFileHeaderLinked *main_file)
{
    JeffClassHeaderLinked *c = NULL, *ci;
    unsigned int i;

    for (i = 0; i < main_file->internal_class_count; i++) {
        ci = main_file->class_header[i];

        if (jeff_is_super_class(class_AEEApplet, ci)
            && (ci->access_flag & JEFF_ACC_PUBLIC)) {
            if (c) {
                jeff_printe_more_than_one_main_class();
                return NULL;
            }

            c = ci;
        }
    }

    if (!c)
        jeff_printe_no_main_class();

    return c;
}

/* Java applet thread main routine */
static void *
app_instance_main(void *arg)
{
    module_data *m_data = (module_data *)arg;
    jeff_applet_data *applet_data = (jeff_applet_data *)m_data->internal_data;
    JeffClassHeaderLinked *object_class;
    JeffMethodLinked *m;
    unsigned int argv[1];
    uint8 argt[1];

    app_manager_printf("Java Applet '%s' started\n", m_data->module_name);

#if BEIHAI_ENABLE_TOOL_AGENT != 0
    if (applet_data->debug_mode)
        jeff_tool_suspend_self();
#endif

    applet_data->vm_instance->applet_object = applet_data->applet_obj;
    object_class = jeff_object_class_pointer(applet_data->applet_obj);
    m = jeff_select_method_virtual(object_class, method_AEEApplet_onInit);
    bh_assert(m != NULL);
    /* Initialize applet class which call <clinit> */
    if (!app_manager_initialize_class(object_class)) {
        app_manager_printf("Call <clinit> fail\n");
        goto fail;
    }

    /* Initialize applet object which call <init> */
    if (!app_manager_initialize_object(applet_data->applet_obj)) {
        app_manager_printf("Call <init> fail\n");
        goto fail;
    }

    /* Call applet's onInit() method */
    argv[0] = (unsigned int)applet_data->applet_obj;
    argt[0] = 1;
    if (app_manager_call_java(m, 1, argv, argt))
        /* Enter queue loop run to receive and process applet queue message
         */
        bh_queue_enter_loop_run(m_data->queue, app_instance_queue_callback);

fail:
    applet_data->vm_instance->applet_object = applet_data->applet_obj;
    object_class = jeff_object_class_pointer(applet_data->applet_obj);
    m = jeff_select_method_virtual(object_class, method_AEEApplet_onDestroy);
    bh_assert(m != NULL);
    /* Call User Applet or AEEApplet onDestroy() method */
    app_manager_call_java(m, 1, argv, argt);
    if (m != method_AEEApplet_onDestroy) {
        /*If 'm' is user onDestroy, then Call AEEApplet.onDestroy() method*/
        app_manager_call_java(method_AEEApplet_onDestroy, 1, argv, argt);
    }
    app_manager_printf("Applet instance main thread exit.\n");
    return NULL;
}

static bool
verify_signature(JeffFileHeader *file, unsigned size)
{
    uint8 *sig;
    unsigned sig_size;

#if BEIHAI_ENABLE_NO_SIGNATURE != 0
    /* no signature */
    if (file->file_signature == 0)
        return true;
#endif

    if (file->file_length != size
#if BEIHAI_ENABLE_NO_SIGNATURE == 0
        || file->file_signature == 0
#endif
        || file->file_signature >= file->file_length)
        return false;

    sig = (uint8 *)file + file->file_signature;
    sig_size = file->file_length - file->file_signature;

    if (0
        == app_manager_signature_verify((uint8_t *)file, file->file_signature,
                                        sig, sig_size))
        return false;

    return true;
}

/* Install Java Applet */
static bool
jeff_module_install(bh_request_msg_t *msg)
{
    unsigned int size, bpk_file_len, main_file_len, heap_size, timeout;
    uint8 *bpk_file;
    JeffFileHeaderLinked *main_file;
    JeffClassHeaderLinked *main_class;
    module_data *m_data;
    jeff_applet_data *applet_data;
    char *applet_name, *applet_perm;
    attr_container_t *attr_cont;
    bool debug = false;

    /* Check url */
    if (!msg->url || strcmp(msg->url, "/applet") != 0) {
        SEND_ERR_RESPONSE(msg->mid, "Install Applet failed: invalid url.");
        return false;
    }

    /* Check payload */
    attr_cont = (attr_container_t *)msg->payload;
    if (!attr_cont
        || !(bpk_file = (uint8 *)attr_container_get_as_bytearray(
                 attr_cont, "bpk", &bpk_file_len))) {
        SEND_ERR_RESPONSE(msg->mid, "Install Applet failed: invalid bpk file.");
        return false;
    }

    /* Check applet name */
    applet_name = attr_container_get_as_string(attr_cont, "name");

    if (!applet_name || strlen(applet_name) == 0) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: invalid applet name.");
        return false;
    }

    if (app_manager_lookup_module_data(applet_name)) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: applet already installed.");
        return false;
    }

    /* TODO: convert bpk file to Jeff file */
    main_file_len = bpk_file_len;
    main_file = APP_MGR_MALLOC(main_file_len);
    if (!main_file) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: allocate memory failed.");
        return false;
    }
    bh_memcpy_s(main_file, main_file_len, bpk_file, main_file_len);

    /* Verify signature */
    if (!verify_signature((JeffFileHeader *)main_file, main_file_len)) {
        SEND_ERR_RESPONSE(
            msg->mid,
            "Install Applet failed: verify Jeff file signature failed.");
        goto fail1;
    }

    /* Load Jeff main file */
    if (!jeff_runtime_load(main_file, main_file_len, false, NULL, NULL)) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: load Jeff file failed.");
        goto fail1;
    }

    /* Find main class */
    main_class = find_main_class(main_file);
    if (!main_class) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: find applet class failed.");
        goto fail2;
    }

    /* Create module data */
    size = offsetof(module_data, module_name) + strlen(applet_name) + 1;
    size = align_uint(size, 4);
    m_data = APP_MGR_MALLOC(size + sizeof(jeff_applet_data));
    if (!m_data) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: allocate memory failed.");
        goto fail2;
    }

    memset(m_data, 0, size + sizeof(jeff_applet_data));
    m_data->module_type = Module_Jeff;
    m_data->internal_data = (uint8 *)m_data + size;
    applet_data = (jeff_applet_data *)m_data->internal_data;
    bh_strcpy_s(m_data->module_name, strlen(applet_name) + 1, applet_name);
    applet_data->main_file = main_file;

    /* Set applet execution timeout */
    timeout = DEFAULT_APPLET_TIMEOUT;
    if (attr_container_contain_key(attr_cont, "execution timeout"))
        timeout = attr_container_get_as_int(attr_cont, "execution timeout");
    m_data->timeout = timeout;

    /* Create applet permissions */
    applet_perm = attr_container_get_as_string(attr_cont, "perm");
    if (applet_perm != NULL) {
        applet_data->perms = APP_MGR_MALLOC(strlen(applet_perm) + 1);
        if (!applet_data->perms) {
            SEND_ERR_RESPONSE(msg->mid,
                              "Install Applet failed: allocate memory for "
                              "applet permissions failed.");
            goto fail3;
        }

        bh_strcpy_s(applet_data->perms, strlen(applet_perm) + 1, applet_perm);
    }

    /* Create applet queue */
    m_data->queue = bh_queue_create();
    if (!m_data->queue) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: create applet queue failed.");
        goto fail3_1;
    }

    /* Set heap size */
    heap_size = DEFAULT_APPLET_HEAP_SIZE;
    if (attr_container_contain_key(attr_cont, "heap size")) {
        heap_size = attr_container_get_as_int(attr_cont, "heap size");
        if (heap_size < MIN_APPLET_HEAP_SIZE)
            heap_size = MIN_APPLET_HEAP_SIZE;
        else if (heap_size > MAX_APPLET_HEAP_SIZE)
            heap_size = MAX_APPLET_HEAP_SIZE;
    }

    m_data->heap_size = heap_size;

    /* Create applet heap */
    m_data->heap = gc_init_for_instance(heap_size);
    if (!m_data->heap) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: create heap failed.");
        goto fail4;
    }

    /* Create applet object */
    applet_data->applet_obj = jeff_object_new(m_data->heap, main_class);
    if (!applet_data->applet_obj) {
        SEND_ERR_RESPONSE(
            msg->mid, "Install Applet failed: create applet object failed.");
        goto fail5;
    }

    /* Initialize watchdog timer */
    if (!watchdog_timer_init(m_data)) {
        SEND_ERR_RESPONSE(
            msg->mid,
            "Install Applet failed: create applet watchdog timer failed.");
        goto fail5;
    }

#if BEIHAI_ENABLE_TOOL_AGENT != 0
    /* Check whether applet is debuggable */
    if (attr_container_contain_key(attr_cont, "debug"))
        debug = attr_container_get_as_bool(attr_cont, "debug");

    applet_data->debug_mode = debug;

    /* Create tool agent queue */
    if (debug && !(applet_data->tool_agent_queue = bh_queue_create())) {
        SEND_ERR_RESPONSE(
            msg->mid, "Install Applet failed: create tool agent queue failed.");
        goto fail5_1;
    }
#endif

    /* Create applet instance */
    applet_data->vm_instance = jeff_runtime_create_instance(
        main_file, m_data->heap, 16, app_instance_main, m_data, NULL);
    if (!applet_data->vm_instance) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: create Java VM failed");
        goto fail6;
    }

    /* Add applet data to applet data list */
    applet_data->vm_instance->applet_object = applet_data->applet_obj;
    app_manager_add_module_data(m_data);
    app_manager_post_applets_update_event();

#if BEIHAI_ENABLE_TOOL_AGENT != 0
    /* Start tool agent thread */
    if (debug
        && !jeff_tool_start_agent(applet_data->vm_instance,
                                  applet_data->tool_agent_queue)) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install Applet failed: start tool agent failed");
        goto fail6;
    }
#endif

    app_manager_printf("Install Applet success!\n");
    app_send_response_to_host(msg->mid, CREATED_2_01, NULL); /* CREATED */
    return true;

fail6:
#if BEIHAI_ENABLE_TOOL_AGENT != 0
    if (debug)
        bh_queue_destroy(applet_data->tool_agent_queue);
#endif

fail5_1:
    watchdog_timer_destroy(&m_data->wd_timer);

fail5:
    gc_destroy_for_instance(m_data->heap);

fail4:
    bh_queue_destroy(m_data->queue, NULL);

fail3_1:
    APP_MGR_FREE(applet_data->perms);

fail3:
    APP_MGR_FREE(applet_data);

fail2:
    jeff_runtime_unload(main_file);

fail1:
    APP_MGR_FREE(main_file);

    return false;
}

static void
cleanup_applet_resource(module_data *m_data)
{
    jeff_applet_data *applet_data = (jeff_applet_data *)m_data->internal_data;

    /* Unload Jeff main file and free it */
    jeff_runtime_unload(applet_data->main_file);
    APP_MGR_FREE(applet_data->main_file);

    /* Destroy queue */
    bh_queue_destroy(m_data->queue, app_instance_queue_free_callback);

    /* Destroy heap */
    gc_destroy_for_instance(m_data->heap);

    /* Destroy watchdog timer */
    watchdog_timer_destroy(&m_data->wd_timer);

    /* Remove module data from module data list and free it */
    app_manager_del_module_data(m_data);
    APP_MGR_FREE(applet_data->perms);
    APP_MGR_FREE(m_data);
}

/* Uninstall Java Applet */
static bool
jeff_module_uninstall(bh_request_msg_t *msg)
{
    module_data *m_data;
    jeff_applet_data *applet_data;
    attr_container_t *attr_cont;
    char *applet_name;
    bool do_not_reply = false;

    /* Check payload and applet name*/
    attr_cont = (attr_container_t *)msg->payload;

    /* Check whether need to reply this request */
    if (attr_container_contain_key(attr_cont, "do not reply me"))
        do_not_reply = attr_container_get_as_bool(attr_cont, "do not reply me");

    /* Check url */
    if (!msg->url || strcmp(msg->url, "/applet") != 0) {
        if (!do_not_reply)
            SEND_ERR_RESPONSE(msg->mid,
                              "Uninstall Applet failed: invalid url.");
        else
            app_manager_printf("Uninstall Applet failed: invalid url.");
        return false;
    }

    if (!attr_cont
        || !(applet_name = attr_container_get_as_string(attr_cont, "name"))
        || strlen(applet_name) == 0) {
        if (!do_not_reply)
            SEND_ERR_RESPONSE(msg->mid,
                              "Uninstall Applet failed: invalid applet name.");
        else
            app_manager_printf("Uninstall Applet failed: invalid applet name.");
        return false;
    }

    m_data = app_manager_lookup_module_data(applet_name);
    if (!m_data) {
        if (!do_not_reply)
            SEND_ERR_RESPONSE(msg->mid,
                              "Uninstall Applet failed: no applet found.");
        else
            app_manager_printf("Uninstall Applet failed: no applet found.");
        return false;
    }

    if (m_data->module_type != Module_Jeff) {
        if (!do_not_reply)
            SEND_ERR_RESPONSE(msg->mid,
                              "Uninstall Applet failed: invlaid module type.");
        else
            app_manager_printf("Uninstall Applet failed: invalid module type.");
        return false;
    }

    if (m_data->wd_timer.is_interrupting) {
        if (!do_not_reply)
            SEND_ERR_RESPONSE(msg->mid,
                              "Uninstall Applet failed: applet is being "
                              "interrupted by watchdog.");
        else
            app_manager_printf("Uninstall Applet failed: applet is being "
                               "interrupted by watchdog.");
        return false;
    }

    /* Exit applet queue loop run */
    bh_queue_exit_loop_run(m_data->queue);

    applet_data = (jeff_applet_data *)m_data->internal_data;
#if BEIHAI_ENABLE_TOOL_AGENT != 0
    /* Exit tool agent queue loop run */
    if (is_tool_agent_running(m_data)) {
        bh_queue_exit_loop_run(applet_data->tool_agent_queue);
    }
#endif

    /* Wait the end of the applet instance and then destroy it */
    if (applet_data->vm_instance->main_file)
        jeff_runtime_wait_for_instance(applet_data->vm_instance, -1);
    jeff_runtime_destroy_instance(applet_data->vm_instance);

    cleanup_applet_resource(m_data);
    app_manager_post_applets_update_event();

    app_manager_printf("Uninstall Applet success!\n");

    if (!do_not_reply)
        app_send_response_to_host(msg->mid, DELETED_2_02, NULL); /* DELETED */
    return true;
}

#define PERM_PREFIX "AEE.permission."

static bool
check_permission_format(const char *perm)
{
    const char *prefix = PERM_PREFIX;
    const char *p;

    if (perm == NULL || strncmp(perm, prefix, strlen(prefix)) != 0
        || *(p = perm + strlen(prefix)) == '\0')
        return false;

    do {
        if (!(*p == '.' || ('A' <= *p && *p <= 'Z')
              || ('a' <= *p && *p <= 'z')))
            return false;
    } while (*++p != '\0');

    return true;
}

static bool
match(const char *haystack, const char *needle, char delim)
{
    const char *p = needle;

    if (haystack == NULL || *haystack == '\0' || needle == NULL
        || *needle == '\0')
        return false;

    while (true) {
        while (true) {
            if ((*haystack == '\0' || *haystack == delim) && *p == '\0') {
                return true;
            }
            else if (*p == *haystack) {
                ++p;
                ++haystack;
            }
            else {
                break;
            }
        }
        while (*haystack != '\0' && *haystack != delim) {
            ++haystack;
        }
        if (*haystack == '\0') {
            return false;
        }
        else {
            ++haystack;
            p = needle;
        }
    }
}

bool
bh_applet_check_permission(const char *perm)
{
    return check_permission_format(perm)
           && match(app_manager_get_jeff_applet_data()->perms,
                    perm + strlen(PERM_PREFIX), ' ');
}

static bool
jeff_module_init()
{
    JeffDescriptorFull d[] = { { JEFF_TYPE_VOID, 0, NULL } };
    JeffDescriptorFull d1[] = { { JEFF_TYPE_OBJECT | JEFF_TYPE_REF, 0, NULL },
                                { JEFF_TYPE_VOID, 0, NULL } };

    /* Resolve class com.intel.aee.AEEApplet */
    class_AEEApplet =
        jeff_runtime_resolve_class_full_name("com.intel.aee.AEEApplet");
    if (!class_AEEApplet) {
        app_manager_printf(
            "App Manager start failed: resolve class AEEApplet failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.Request */
    class_AEERequest =
        jeff_runtime_resolve_class_full_name("com.intel.aee.Request");
    if (!class_AEERequest) {
        app_manager_printf(
            "App Manager start failed: resolve class Request failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.Timer */
    class_Timer = jeff_runtime_resolve_class_full_name("com.intel.aee.Timer");
    if (!class_Timer) {
        app_manager_printf(
            "App Manager start failed: resolve class Timer failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.Sensor */
    class_Sensor = jeff_runtime_resolve_class_full_name("com.intel.aee.Sensor");
    if (!class_Sensor) {
        app_manager_printf(
            "App Manager start failed: resolve class Sensor failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.ble.BLEManager */
    class_BLEManager =
        jeff_runtime_resolve_class_full_name("com.intel.aee.ble.BLEManager");
    if (!class_BLEManager) {
        app_manager_printf(
            "App Manager start failed: resolve class BLEManager failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.ble.BLEDevice */
    class_BLEDevice =
        jeff_runtime_resolve_class_full_name("com.intel.aee.ble.BLEDevice");
    if (!class_BLEDevice) {
        app_manager_printf(
            "App Manager start failed: resolve class BLEDevice failed.\n");
        return false;
    }
    /* Resolve class com.intel.aee.ble.BLEDevice */
    class_BLEGattService = jeff_runtime_resolve_class_full_name(
        "com.intel.aee.ble.BLEGattService");
    if (!class_BLEGattService) {
        app_manager_printf("App Manager start failed: resolve class "
                           "BLEGattService failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.ble.BLEDevice */
    class_BLEGattCharacteristic = jeff_runtime_resolve_class_full_name(
        "com.intel.aee.ble.BLEGattCharacteristic");
    if (!class_BLEGattCharacteristic) {
        app_manager_printf("App Manager start failed: resolve class "
                           "BLEGattCharacteristic failed.\n");
        return false;
    }

    /* Resolve class com.intel.aee.ble.BLEDevice */
    class_BLEGattDescriptor = jeff_runtime_resolve_class_full_name(
        "com.intel.aee.ble.BLEGattDescriptor");
    if (!class_BLEGattDescriptor) {
        app_manager_printf("App Manager start failed: resolve class "
                           "BLEGattDescriptor failed.\n");
        return false;
    }
    /* Resolve class com.intel.aee.gpio.GPIOChannel */
    class_GPIOChannel =
        jeff_runtime_resolve_class_full_name("com.intel.aee.gpio.GPIOChannel");
    if (!class_GPIOChannel) {
        app_manager_printf("App Manager start failed: resolve class "
                           "GPIOChannel failed.\n");
        return false;
    }

    /* Resolve method com.intel.aee.AEEApplet.onInit() */
    method_AEEApplet_onInit =
        jeff_lookup_method(class_AEEApplet, "onInit", 0, d);
    if (!method_AEEApplet_onInit) {
        app_manager_printf("App Manager start failed: resolve method "
                           "Applet.onInit() failed.\n");
        return false;
    }

    /* Resolve method com.intel.aee.AEEApplet.onDestroy() */
    method_AEEApplet_onDestroy =
        jeff_lookup_method(class_AEEApplet, "onDestroy", 0, d);
    if (!method_AEEApplet_onDestroy) {
        app_manager_printf("App Manager start failed: resolve method "
                           "AEEApplet.onDestroy() failed.\n");
        return false;
    }

    /* Resolve method com.intel.aee.AEEApplet.callOnRequest(Request) */
    d1[0].class_header = class_AEERequest;
    method_AEEApplet_callOnRequest =
        jeff_lookup_method(class_AEEApplet, "callOnRequest", 1, d1);
    if (!method_AEEApplet_callOnRequest) {
        app_manager_printf("App Manager start failed: resolve method "
                           "AEEApplet.callOnRequest() failed.\n");
        return false;
    }

    /* Resolve method com.intel.aee.Timer.callOnTimer() */
    method_callOnTimer = jeff_lookup_method(class_Timer, "callOnTimer", 0, d);
    if (!method_callOnTimer) {
        app_manager_printf("App Manager start failed: resolve method "
                           "Timer.callOnTimer() failed.\n");
        return false;
    }

    /* Resolve method com.intel.aee.Sensor.callOnSensorEvent() */
    method_callOnSensorEvent =
        jeff_lookup_method(class_Sensor, "callOnSensorEvent", 0, d);
    if (!method_callOnSensorEvent) {
        app_manager_printf("App Manager start failed: resolve method "
                           "Sensor.callOnSensorEvent() failed.\n");
        return false;
    }

    /* Resovle method
     * com.intel.aee.ble.BLEManager.callOnBLEStartDiscovery(BLEDevice) */
    d1[0].class_header = class_BLEDevice;
    method_callOnBLEStartDiscovery =
        jeff_lookup_method(class_BLEManager, "callOnBLEStartDiscovery", 1, d1);
    if (!method_callOnBLEStartDiscovery) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.callOnBLEStartDiscovery() failed.\n");
        return false;
    }

    /* Resovle method
     * com.intel.aee.ble.BLEManager.callOnBLEConnected(BLEDevice) */
    JeffDescriptorFull d2_1[] = { { JEFF_TYPE_OBJECT | JEFF_TYPE_REF, 0,
                                    class_BLEDevice },
                                  { JEFF_TYPE_INT, 0, NULL },
                                  { JEFF_TYPE_VOID, 0, NULL } };
    method_callOnBLEConnected =
        jeff_lookup_method(class_BLEManager, "callOnBLEConnected", 2, d2_1);
    if (!method_callOnBLEConnected) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.callOnBLEConnected() failed.\n");
        return false;
    }

    /* Resovle method
     * com.intel.aee.ble.BLEManager.method_callOnBLENotification(BLEDevice,byte[])
     */
    JeffDescriptorFull d2_2[] = {
        { JEFF_TYPE_OBJECT | JEFF_TYPE_REF, 0, class_BLEDevice },
        { JEFF_TYPE_BYTE | JEFF_TYPE_REF | JEFF_TYPE_MONO, 1, NULL },
        { JEFF_TYPE_INT, 0, NULL },
        { JEFF_TYPE_INT, 0, NULL },
        { JEFF_TYPE_VOID, 0, NULL }
    };
    method_callOnBLENotification =
        jeff_lookup_method(class_BLEManager, "callOnBLENotification", 4, d2_2);
    if (!method_callOnBLENotification) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.callOnBLENotification() failed.\n");
        return false;
    }

    /* Resovle method
     * com.intel.aee.ble.BLEManager.callOnBLEConnected(BLEDevice,byte[]) */
    method_callOnBLEIndication =
        jeff_lookup_method(class_BLEManager, "callOnBLEIndication", 4, d2_2);
    if (!method_callOnBLEIndication) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.callOnBLEIndication() failed.\n");
        return false;
    }

    /* Resovle method
     * com.intel.aee.ble.BLEManager.callOnBLEConnected(BLEDevice) */
    d1[0].class_header = class_BLEDevice;
    method_callOnBLEDisconnected =
        jeff_lookup_method(class_BLEManager, "callOnBLEDisconnected", 1, d1);
    if (!method_callOnBLEDisconnected) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.callOnBLEDisconnected() failed.\n");
        return false;
    }

    /* Resovle method
     * com.intel.aee.ble.BLEManager.callOnBLEConnected(BLEDevice) */
    method_callOnBLEPasskeyEntry =
        jeff_lookup_method(class_BLEManager, "callOnBLEPasskeyEntry", 1, d1);
    if (!method_callOnBLEPasskeyEntry) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.callOnBLEPasskeyEntry() failed.\n");
        return false;
    }
    /* Resovle  method void
     * com.intel.aee.gpio.GPIOChannel.callOnGPIOInterrupt()  */
    method_callOnGPIOInterrupt =
        jeff_lookup_method(class_GPIOChannel, "callOnGPIOInterrupt", 0, d);
    if (!method_callOnGPIOInterrupt) {
        app_manager_printf("App Manager start failed: resolve method "
                           "GPIOChannel.callOnGPIOInterrupt() failed.\n");
        return false;
    }

    JeffDescriptorFull d2[] = {
        { JEFF_TYPE_BYTE | JEFF_TYPE_REF | JEFF_TYPE_MONO, 1, NULL },
        { JEFF_TYPE_OBJECT | JEFF_TYPE_REF, 0, class_BLEDevice }
    };
    /* Resovle method com.intel.aee.ble.BLEManager.getBLEDevice(byte []) */
    method_callOnBLEManagerGetBLEDevice =
        jeff_lookup_method(class_BLEManager, "getBLEDevice", 1, d2);
    if (!method_callOnBLEManagerGetBLEDevice) {
        app_manager_printf("App Manager start failed: resolve method "
                           "BLEManager.getBLEDevice() failed.\n");
        return false;
    }

    return true;
}

static void
jeff_module_watchdog_kill(module_data *m_data)
{
    jeff_applet_data *applet_data = (jeff_applet_data *)m_data->internal_data;

    app_manager_printf("Watchdog interrupt the applet %s\n",
                       m_data->module_name);

    jeff_runtime_interrupt_instance(applet_data->vm_instance, true);

    /* Exit applet queue loop run */
    bh_queue_exit_loop_run(m_data->queue);

    /* Wait the end of the applet instance. If timeout, it means applet
     * is busy executing native code, then try to cancle the main thread. */
    if (applet_data->vm_instance->main_file)
        jeff_runtime_wait_for_instance(applet_data->vm_instance, 3000);

    if (applet_data->vm_instance->main_file) {
        app_manager_printf("Watchdog cancel applet main thread.\n");
        os_thread_cancel(applet_data->vm_instance->main_tlr.handle);
        /* k_thread_abort(applet_data->vm_instance->main_tlr.handle); */
    }

    send_exception_event_to_host(m_data->module_name,
                                 "java.lang.InterruptedException");
    cleanup_applet_resource(m_data);
    app_manager_printf("Watchdog interrupt Jeff applet done.\n");
}

static bool
jeff_module_handle_host_url(void *queue_msg)
{
#if BEIHAI_ENABLE_TOOL_AGENT != 0
    bh_queue_msg_t *msg = (bh_queue_msg_t *)queue_msg;

    if (msg->message_type == COAP_PARSED) {
        coap_packet_t *packet = (coap_packet_t *)msg->payload;
        attr_container_t *attr_cont = (attr_container_t *)packet->payload;
        const char *url = NULL;
        int url_len = 0, mid;

        bh_memcpy_s(&mid, sizeof(uint32), packet->token, sizeof(uint32));
        url_len = coap_get_header_uri_path(packet, &url);

        /* Send request to tool agent */
        if (url_len >= 12 && memcmp(url, "/tool_agent/", 12) == 0) {
            module_data *m_data;
            jeff_applet_data *applet_data;
            unsigned attr_cont_len = 0, req_msg_len;
            bh_queue_msg_t *tool_agent_msg;
            bh_request_msg_t *req_msg;
            char url_buf[256] = { 0 }, *p = url_buf;
            char applet_name[128] = { 0 };

            /* Resolve applet name */
            bh_memcpy_s(url_buf, sizeof(url_buf), url + 12, url_len - 12);
            while (*p != '/' && *p != '\0')
                p++;

            bh_memcpy_s(applet_name, sizeof(applet_name), url_buf, p - url_buf);
            app_manager_printf("Send request to tool agent of applet: %s\n",
                               applet_name);

            /* Check applet name */
            if (!(m_data = app_manager_lookup_module_data(applet_name))) {
                SEND_ERR_RESPONSE(mid, "Send request to tool agent failed: "
                                       "invalid applet name");
                return false;
            }

            applet_data = (jeff_applet_data *)m_data->internal_data;
            /* Attach debug: start the tool agent firstly */
            if (packet->code == COAP_PUT) {
                if (is_tool_agent_running(m_data)) {
                    SEND_ERR_RESPONSE(mid, "Attach debug failed: tool "
                                           "agent is already exist.");
                    return false;
                }

                applet_data->debug_mode = true;

                /* Create tool agent queue */
                if (!(applet_data->tool_agent_queue = bh_queue_create())) {
                    SEND_ERR_RESPONSE(mid, "Attach debug failed: create "
                                           "tool agent queue failed.");
                    return false;
                }

                /* Start tool agent thread */
                if (!jeff_tool_start_agent(applet_data->vm_instance,
                                           applet_data->tool_agent_queue)) {
                    bh_queue_destroy(applet_data->tool_agent_queue, NULL);
                    SEND_ERR_RESPONSE(
                        mid, "Attach debug failed: start tool agent failed");
                    return false;
                }

                app_manager_printf("Attach debug: start tool agent of "
                                   "applet %s success.\n",
                                   applet_name);
                app_send_response_to_host(mid, CREATED_2_01, NULL); /* OK */
            }
            else {
                /* Check tool agent running */
                if (!is_tool_agent_running(m_data)) {
                    SEND_ERR_RESPONSE(mid, "Send request to tool agent failed: "
                                           "tool agent is not running");
                    return false;
                }

                /* Create queue message for tool agent */
                if (!(tool_agent_msg =
                          APP_MGR_MALLOC(sizeof(bh_queue_msg_t)))) {
                    SEND_ERR_RESPONSE(mid, "Send request to tool agent failed: "
                                           "allocate memory failed");
                    return false;
                }

                if (attr_cont)
                    attr_cont_len =
                        attr_container_get_serialize_length(attr_cont);

                req_msg_len =
                    sizeof(bh_request_msg_t) + strlen(p) + 1 + attr_cont_len;

                /* Create request message */
                if (!(req_msg = APP_MGR_MALLOC(req_msg_len))) {
                    SEND_ERR_RESPONSE(mid, "Send request to applet failed: "
                                           "allocate memory failed");
                    APP_MGR_FREE(tool_agent_msg);
                    return false;
                }

                /* Set request message */
                memset(req_msg, 0, req_msg_len);
                req_msg->mid = mid;
                req_msg->url = (char *)req_msg + sizeof(bh_request_msg_t);
                bh_strcpy_s(req_msg->url, strlen(p) + 1,
                            p); /* Actual url sent to tool agent */
                req_msg->action = packet->code;
                req_msg->fmt = 0;
                if (attr_cont) {
                    req_msg->payload = (char *)req_msg
                                       + sizeof(bh_request_msg_t) + strlen(p)
                                       + 1;
                    attr_container_serialize(req_msg->payload, attr_cont);
                }

                /* Set queue message and send to tool agent's queue */
                tool_agent_msg->message_type = JDWP_REQUEST;
                tool_agent_msg->payload_size = req_msg_len;
                tool_agent_msg->payload = (char *)req_msg;
                if (!bh_queue_send_message(applet_data->tool_agent_queue,
                                           tool_agent_msg)) {
                    APP_MGR_FREE(req_msg);
                    APP_MGR_FREE(tool_agent_msg);
                    SEND_ERR_RESPONSE(mid, "Send request to tool agent failed: "
                                           "send queue msg failed.");
                    return false;
                }

                /* app_manager_printf("Send request to tool agent of applet
                 * %s success.\n", applet_name); */
            }

            return true;
        }
    }
#endif /* BEIHAI_ENABLE_TOOL_AGENT != 0 */
    return false;
}

static module_data *
jeff_module_get_module_data(void)
{
    JeffThreadLocalRoot *self = jeff_runtime_get_tlr();
    return (module_data *)self->il_root->start_routine_arg;
}

#if BEIHAI_ENABLE_TOOL_AGENT != 0

#define JDWP_HANDSHAKE_MAGIC "JDWP-Handshake"
#define JDWP_HANDSHAKE_LEN (sizeof(JDWP_HANDSHAKE_MAGIC) - 1)

#define JDWP_PAYLOAD_KEY "jdwp"

static bool debug = true;

static bool
send_msg_to_host(int mid, const char *url, int code, const uint8 *msg,
                 unsigned size)
{
    bool ret;
    int payload_len = 0;
    attr_container_t *payload = NULL;

    if (msg) {
        if ((payload = attr_container_create(""))) {
            attr_container_set_bytearray(&payload, JDWP_PAYLOAD_KEY,
                                         (const int8_t *)msg, size);
            payload_len = attr_container_get_serialize_length(payload);
        }
    }
    ret = app_send_msg_to_host(mid, url, code, (char *)payload, payload_len);

    if (payload)
        attr_container_destroy(payload);

    return ret;
}

static bool
send_response(int mid, int code, const uint8 *msg, unsigned size)
{
    return send_msg_to_host(mid, NULL, code, msg, size);
}

static bool
send_packet_response(int mid, int code, JeffBuffer *packet)
{
    int size;

    if ((size = jeff_buffer_size(packet)) == 0)
        /* No data need to be written, succeed.  */
        return true;

    return send_msg_to_host(mid, NULL, code, jeff_buffer_at(packet, 0), size);
}

void
jeff_tool_event_publish(uint8 *evtbuf, unsigned size)
{
    char *prefix = "/jdwp/", *url = NULL;
    int url_len;

    url_len = strlen(prefix) + strlen(app_manager_get_module_name(Module_Jeff));
    if (NULL == (url = jeff_runtime_malloc(url_len + 1)))
        return;

    bh_strcpy_s(url, url_len + 1, prefix);
    bh_strcat_s(url, url_len + 1, app_manager_get_module_name(Module_Jeff));

    /* Event is sent as request so we set code as COAP_PUT */
    if (event_is_registered(url))
        send_msg_to_host(0, url, COAP_PUT, evtbuf, size);

    jeff_runtime_free(url);
}

#define SEND_ERROR_RESPONSE(err_msg)                            \
    do {                                                        \
        app_manager_printf("%s\n", err_msg);                    \
        send_response(req_msg->mid, INTERNAL_SERVER_ERROR_5_00, \
                      (uint8 *)err_msg, strlen(err_msg) + 1);   \
    } while (0)

/* Queue callback of tool agent */
void
tool_agent_queue_callback(void *arg)
{
    bh_queue_msg_t *msg = (bh_queue_msg_t *)arg;

    if (msg->message_type == JDWP_REQUEST) {
        bh_request_msg_t *req_msg = (bh_request_msg_t *)msg->payload;
        attr_container_t *attr_cont = (attr_container_t *)req_msg->payload;
        JeffThreadLocalRoot *self = jeff_runtime_get_tlr();
        JeffInstanceLocalRoot *cur_instance = self->il_root;
        JeffToolAgent *agent = cur_instance->tool_agent;
        bh_queue *queue = (bh_queue *)self->start_routine_arg;

        if (debug)
            app_manager_printf(
                "Tool Agent of applet %s got request, url %s, action %d\n",
                app_manager_get_module_name(Module_Jeff), req_msg->url,
                req_msg->action);

        /* Handshake or Process Request */
        if (req_msg->action == COAP_GET) {
            uint8 *buf;
            unsigned buf_len;

            if (!attr_cont
                || !(buf = (uint8 *)attr_container_get_as_bytearray(
                         attr_cont, JDWP_PAYLOAD_KEY, &buf_len))) {
                SEND_ERROR_RESPONSE("Tool Agent fail: invalid JDWP payload.");
                goto fail;
            }

            if (!agent->connected) {
                if (buf_len != JDWP_HANDSHAKE_LEN
                    || memcmp(buf, JDWP_HANDSHAKE_MAGIC, JDWP_HANDSHAKE_LEN)) {
                    SEND_ERROR_RESPONSE("Tool Agent fail: handshake fail.");
                    goto fail;
                }

                /* Handshake success and response */
                agent->connected = true;
                send_response(req_msg->mid, CONTENT_2_05, buf, buf_len);
            }
            else {
                /* TODO: tool-agent thread should reuse the request/reply
                 * buffer to avoid allocating memory repeatedly */
                JeffBuffer request, reply;

                /* Initialize the package buffers. */
                jeff_buffer_init(&request);
                jeff_buffer_init(&reply);

                if (!jeff_buffer_resize(&request, buf_len)) {
                    SEND_ERROR_RESPONSE("Tool Agent fail: resize buffer fail.");
                    jeff_buffer_destroy(&request);
                    jeff_buffer_destroy(&reply);
                    goto fail;
                }

                /* Copy data from request to jeff buffer */
                bh_memcpy_s(jeff_buffer_at(&request, 0),
                            jeff_buffer_size(&request), buf, buf_len);

                /* Handle JDWP request */
                if (!jeff_tool_handle_packet(agent, &request, &reply)) {
                    SEND_ERROR_RESPONSE(
                        "Tool agent fail: handle request fail.");
                    jeff_buffer_destroy(&request);
                    jeff_buffer_destroy(&reply);
                    goto fail;
                }

                /* Response JDWP reply */
                send_packet_response(req_msg->mid, CONTENT_2_05, &reply);

                /* Destroy the package buffers. */
                jeff_buffer_destroy(&request);
                jeff_buffer_destroy(&reply);
            }
        }
        /* Debugger disconnect */
        else if (req_msg->action == COAP_DELETE) {
            send_response(req_msg->mid, DELETED_2_02, NULL, 0);
            bh_queue_exit_loop_run(queue);
        }
        else {
            SEND_ERROR_RESPONSE("Tool agent fail: invalid request.");
            goto fail;
        }

        APP_MGR_FREE(req_msg);
        APP_MGR_FREE(msg);
        return;

    fail:
        bh_queue_exit_loop_run(queue);
        APP_MGR_FREE(req_msg);
    }

    APP_MGR_FREE(msg);
}

void
tool_agent_queue_free_callback(void *message)
{
    bh_queue_msg_t *msg = (bh_queue_msg_t *)message;

    if (msg->message_type == JDWP_REQUEST) {
        bh_request_msg_t *req_msg = (bh_request_msg_t *)msg->payload;
        APP_MGR_FREE(req_msg);
    }

    APP_MGR_FREE(msg);
}

#endif /* BEIHAI_ENABLE_TOOL_AGENT != 0 */

/* clang-format off */
module_interface jeff_module_interface = {
    jeff_module_init,
    jeff_module_install,
    jeff_module_uninstall,
    jeff_module_watchdog_kill,
    jeff_module_handle_host_url,
    jeff_module_get_module_data,
    NULL
};
/* clang-format on */

#endif

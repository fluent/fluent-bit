/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#if 0

#define BLUETOOTH_INTERFACE_ADVERTISMENT_DATA_LENGTH 31
/* ble_device_info */
typedef struct ble_device_info {

    /* address type */
    uint8_t address_type;
    /* MAC of Device */
    uint8_t mac[6];
    /* security level */
    uint8_t security_level;
    /* signal strength */
    int8_t rssi;
    /* uuid_16_type */
    int8_t uuid_16_type;
    /* uuid_32_type */
    int8_t uuid_32_type;
    /* uuid_128_type */
    int8_t uuid_128_type;
    /* error code */
    uint8_t error_code;
    /* scan response length*/
    uint16_t adv_data_len;
    /* advertisement data */
    uint8_t *adv_data;
    /* scan response length*/
    uint16_t scan_response_len;
    /* scan response */
    uint8_t *scan_response;
    /* next device */
    struct ble_device_info *next;
    /* private data length */
    int private_data_length;
    /* private data */
    uint8_t *private_data;
    /* value handle*/
    uint16_t value_handle;
    /* ccc handle*/
    uint16_t ccc_handle;

}ble_device_info;

/* BLE message sub type */
typedef enum BLE_SUB_EVENT_TYPE {
    BLE_SUB_EVENT_DISCOVERY,
    BLE_SUB_EVENT_CONNECTED,
    BLE_SUB_EVENT_DISCONNECTED,
    BLE_SUB_EVENT_NOTIFICATION,
    BLE_SUB_EVENT_INDICATION,
    BLE_SUB_EVENT_PASSKEYENTRY,
    BLE_SUB_EVENT_SECURITY_LEVEL_CHANGE
}BLE_SUB_EVENT_TYPE;

/* Queue message, for BLE Event */
typedef struct bh_queue_ble_sub_msg_t {
    /* message type, should be one of QUEUE_MSG_TYPE */
    BLE_SUB_EVENT_TYPE type;
    /* payload size */
    /*uint32_t payload_size;*/
    char payload[1];
}bh_queue_ble_sub_msg_t;

static void
app_instance_free_ble_msg(char *msg)
{
    bh_queue_ble_sub_msg_t *ble_msg = (bh_queue_ble_sub_msg_t *)msg;
    ble_device_info *dev_info;

    dev_info = (ble_device_info *) ble_msg->payload;

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
app_instance_queue_free_callback(bh_message_t queue_msg)
{

    char * payload = (char *)bh_message_payload(queue_msg);
    if(payload == NULL)
    return;

    switch (bh_message_type(queue_msg))
    {
        /*
         case SENSOR_EVENT: {
         bh_sensor_event_t *sensor_event = (bh_sensor_event_t *) payload;
         attr_container_t *event = sensor_event->event;
         attr_container_destroy(event);
         }
         break;
         */
        case BLE_EVENT: {
            app_instance_free_ble_msg(payload);
            break;
        }
    }
}

#endif

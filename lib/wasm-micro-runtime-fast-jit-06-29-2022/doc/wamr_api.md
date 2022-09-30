
WAMR application framework
========================

## Application system callbacks
The `on_init` and `on_destroy` functions are wamr application system callbacks which must be implemented in the wasm application if you want to use the APP framework.
``` C
void on_init()
{
    /*
        Your init functions here, for example:
        * platform initialization
        * timer registration
        * service / event registration
        * ......
    */
}

void on_destroy()
{
    /*
        your destroy functions here
    */
}
```

## Base App library

The base library of application framework supports the essential API for WASM applications, such as inter-app communication, timers, etc. Other application framework components rely on the base library.

When building the WAMR SDK, once application framework is enabled, the base library will automatically enabled.

### Timer
The *timer* API's can be used to create some `soft timers` with single-shot mode or periodic mode. Here is a reference of how to use timer API's to execute a function every one second.
``` C
/* User global variable */
static int num = 0;

/* Timer callback */
void timer1_update(user_timer_t timer)
{
    printf("Timer update %d\n", num++);
}

void on_init()
{
    user_timer_t timer;

    /* set up a timer */
    timer = api_timer_create(1000, true, false, timer1_update);
    api_timer_restart(timer, 1000);
}

void on_destroy()
{

}
```

### Micro-service model (request/response)
The microservice model is also known as request and response model. One WASM application acts as the server which provides a specific service. Other WASM applications or host/cloud applications request that service and get the response.

<center><img src="./pics/request.PNG" width="60%" height="60%"></center>

Below is the reference implementation of the server application. It provides room temperature measurement service.

``` C
void on_init()
{
    api_register_resource_handler("/room_temp", room_temp_handler);
}

void on_destroy() 
{
}

void room_temp_handler(request_t *request)
{
    response_t response[1];
    attr_container_t *payload;
    payload = attr_container_create("room_temp payload");
    if (payload == NULL)
        return;

    attr_container_set_string(&payload, "temp unit", "centigrade");
    attr_container_set_int(&payload, "value", 26);

    make_response_for_request(request, response);
    set_response(response,
                 CONTENT_2_05,
                 FMT_ATTR_CONTAINER,
                 payload,
                 attr_container_get_serialize_length(payload));

    api_response_send(response);
    attr_container_destroy(payload);
}
```


### Pub/sub model
One WASM application acts as the event publisher. It publishes events to notify WASM applications or host/cloud applications which subscribe to the events.

<center><img src="./pics/sub.PNG" width="60%" height="60%"></center>

Below is the reference implementation of the pub application. It utilizes a timer to repeatedly publish an overheat alert event to the subscriber applications. Then the subscriber applications receive the events immediately.

``` C
/* Timer callback */
void timer_update(user_timer_t timer)
{
    attr_container_t *event;

    event = attr_container_create("event");
    attr_container_set_string(&event,
                              "warning",
                              "temperature is over high");

    api_publish_event("alert/overheat",
                      FMT_ATTR_CONTAINER,
                      event,
                      attr_container_get_serialize_length(event));

    attr_container_destroy(event);
}

void on_init()
{
    user_timer_t timer;
    timer = api_timer_create(1000, true, true, timer_update);
}

void on_destroy()
{
}
```

Below is the reference implementation of the sub application.
``` C
void overheat_handler(request_t *event)
{
    printf("Event: %s\n", event->url);

    if (event->payload != NULL && event->fmt == FMT_ATTR_CONTAINER)
       attr_container_dump((attr_container_t *) event->payload);
}

void on_init(
{
    api_subscribe_event ("alert/overheat", overheat_handler);
}

void on_destroy()
{
}
```
**Note:** You can also subscribe this event from host side by using host tool. Please refer `samples/simple` project for detail usage.


## Sensor API

The API set is defined in the header file ```core/app-framework/sensor/app/wa-inc/sensor.h```.

Here is a reference of how to use sensor API's:

``` C
static sensor_t sensor = NULL;

/* Sensor event callback*/
void sensor_event_handler(sensor_t sensor, attr_container_t *event,
                          void *user_data)
{
    printf("### app get sensor event\n");
    attr_container_dump(event);
}

void on_init()
{
    char *user_data;
    attr_container_t *config;

    printf("### app on_init 1\n");
    /* open a sensor */
    user_data = malloc(100);
    printf("### app on_init 2\n");
    sensor = sensor_open("sensor_test", 0, sensor_event_handler, user_data);
    printf("### app on_init 3\n");

    /* config the sensor */
    sensor_config(sensor, 1000, 0, 0);
    printf("### app on_init 4\n");
}

void on_destroy()
{
    if (NULL != sensor) {
        sensor_config(sensor, 0, 0, 0);
    }
}
```

## Connection API: 

The API set is defined in the header file `core/app-framework/connection/app/wa-inc/connection.h`

Here is a reference of how to use connection API's:
``` C
/* User global variable */
static int num = 0;
static user_timer_t g_timer;
static connection_t *g_conn = NULL;

void on_data1(connection_t *conn,
              conn_event_type_t type,
              const char *data,
              uint32 len,
              void *user_data)
{
    if (type == CONN_EVENT_TYPE_DATA) {
        char message[64] = {0};
        memcpy(message, data, len);
        printf("Client got a message from server -> %s\n", message);
    } else if (type == CONN_EVENT_TYPE_DISCONNECT) {
        printf("connection is close by server!\n");
    } else {
        printf("error: got unknown event type!!!\n");
    }
}

/* Timer callback */
void timer1_update(user_timer_t timer)
{
    char message[64] = {0};
    /* Reply to server */
    snprintf(message, sizeof(message), "Hello %d", num++);
    api_send_on_connection(g_conn, message, strlen(message));
}

void my_close_handler(request_t * request)
{
    response_t response[1];

    if (g_conn != NULL) {
        api_timer_cancel(g_timer);
        api_close_connection(g_conn);
    }

    make_response_for_request(request, response);
    set_response(response, DELETED_2_02, 0, NULL, 0);
    api_response_send(response);
}

void on_init()
{
    user_timer_t timer;
    attr_container_t *args;
    char *str = "this is client!";

    api_register_resource_handler("/close", my_close_handler);

    args = attr_container_create("");
    attr_container_set_string(&args, "address", "127.0.0.1");
    attr_container_set_uint16(&args, "port", 7777);

    g_conn = api_open_connection("TCP", args, on_data1, NULL);
    if (g_conn == NULL) {
        printf("connect to server fail!\n");
        return;
    }

    printf("connect to server success! handle: %p\n", g_conn);

    /* set up a timer */
    timer = api_timer_create(1000, true, false, timer1_update);
    api_timer_restart(timer, 1000);
}

void on_destroy()
{

}
```

## GUI API

The API's is listed in header file ```core/app-framework/wgl/app/wa-inc/wgl.h``` which is implemented based on open source 2D graphic library [LVGL](https://docs.lvgl.io/master/index.html).

``` C
static void btn_event_cb(wgl_obj_t btn, wgl_event_t event);

uint32_t count = 0;
char count_str[11] = { 0 };
wgl_obj_t hello_world_label;
wgl_obj_t count_label;
wgl_obj_t btn1;
wgl_obj_t label_count1;
int label_count1_value = 0;
char label_count1_str[11] = { 0 };

void timer1_update(user_timer_t timer1)
{
    if ((count % 100) == 0) {
        snprintf(count_str, sizeof(count_str), "%d", count / 100);
        wgl_label_set_text(count_label, count_str);
    }
    ++count;
}

void on_init()
{
    hello_world_label = wgl_label_create((wgl_obj_t)NULL, (wgl_obj_t)NULL);
    wgl_label_set_text(hello_world_label, "Hello world!");
    wgl_obj_align(hello_world_label, (wgl_obj_t)NULL, WGL_ALIGN_IN_TOP_LEFT, 0, 0);

    count_label = wgl_label_create((wgl_obj_t)NULL, (wgl_obj_t)NULL);
    wgl_obj_align(count_label, (wgl_obj_t)NULL, WGL_ALIGN_IN_TOP_MID, 0, 0);

    btn1 = wgl_btn_create((wgl_obj_t)NULL, (wgl_obj_t)NULL); /*Create a button on the currently loaded screen*/
    wgl_obj_set_event_cb(btn1, btn_event_cb); /*Set function to be called when the button is released*/
    wgl_obj_align(btn1, (wgl_obj_t)NULL, WGL_ALIGN_CENTER, 0, 0); /*Align below the label*/

    /*Create a label on the button*/
    wgl_obj_t btn_label = wgl_label_create(btn1, (wgl_obj_t)NULL);
    wgl_label_set_text(btn_label, "Click ++");

    label_count1 = wgl_label_create((wgl_obj_t)NULL, (wgl_obj_t)NULL);
    wgl_label_set_text(label_count1, "0");
    wgl_obj_align(label_count1, (wgl_obj_t)NULL, WGL_ALIGN_IN_BOTTOM_MID, 0, 0);

    /* set up a timer */
    user_timer_t timer;
    timer = api_timer_create(10, true, false, timer1_update);
    if (timer)
        api_timer_restart(timer, 10);
    else
        printf("Fail to create timer.\n");
}

static void btn_event_cb(wgl_obj_t btn, wgl_event_t event)
{
    if(event == WGL_EVENT_RELEASED) {
        label_count1_value++;
        snprintf(label_count1_str, sizeof(label_count1_str),
                 "%d", label_count1_value);
        wgl_label_set_text(label_count1, label_count1_str);
    }
}

```

Currently supported widgets include button, label, list and check box and more widgets would be provided in future.

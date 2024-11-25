/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "host_api.h"
#include "bi-inc/attr_container.h"
#include "er-coap-constants.h"

static char *
read_file_to_buffer(const char *filename, int *ret_size);
int send_request_to_applet_success = 0;
const char *label_for_request = "request1";
int event_listener_counter = 0;
char *applet_buf[1024 * 1024];
const char *host_agent_ip = "127.0.0.1";
void
f_aee_response_handler(void *usr_ctx, aee_response_t *response)
{
    if (response == NULL) {
        printf("########## request timeout!!! \n");
    }
    else {
        char *str = (char *)usr_ctx;
        printf("#### dump response ####\n");
        printf("#### user data: %s \n", str);
        printf("#### status: %d \n", response->status);
        if (response->payload != NULL)
            attr_container_dump((attr_container_t *)response->payload);
    }
}

void
f_aee_event_listener(const char *url, void *event, int fmt)
{
    printf("######## event is received. url: %s, fmt:%d ############\n", url,
           fmt);

    attr_container_t *attr_obj = (attr_container_t *)event;

    attr_container_dump(attr_obj);
    /*
     if (0 == strcmp(url, "alert/overheat"))
     {
     event_listener_counter++;
     printf("event :%d \n", event_listener_counter);
     }
     */
}

static int
print_menu_and_select(void)
{
    char s[256];
    int choice;
    do {
        printf("\n");
        printf("1. Install TestApplet1\n");
        printf("2. Install TestApplet2\n");
        printf("3. Install TestApplet3\n");
        printf("4. Uninstall TestApplet1\n");
        printf("5. Uninstall TestApplet2\n");
        printf("6. Uninstall TestApplet3\n");
        printf("7. Send Request to TestApplet1\n");
        printf("8. Register Event to TestApplet1\n");
        printf("9. UnRegister Event to TestApplet1\n");
        printf("a. Query Applets\n");
        printf("t. Auto Test\n");
        printf("q. Exit\n");
        printf("Please Select: ");

        if (fgets(s, sizeof(s), stdin)) {
            if (!strncmp(s, "q", 1))
                return 0;
            if (!strncmp(s, "a", 1))
                return 10;
            if (!strncmp(s, "t", 1))
                return 20;
            choice = atoi(s);
            if (choice >= 1 && choice <= 9)
                return choice;
        }
    } while (1);
    return 0;
}

static void
install_applet(int index)
{
    char applet_name[64];
    char applet_file_name[64];
    char *buf;
    int size;
    int ret;

    printf("Installing TestApplet%d...\n", index);
    snprintf(applet_name, sizeof(applet_name), "TestApplet%d", index);
    snprintf(applet_file_name, sizeof(applet_file_name), "./TestApplet%d.wasm",
             index);
    buf = read_file_to_buffer(applet_file_name, &size);
    if (!buf) {
        printf("Install Applet failed: read file %s error.\n",
               applet_file_name);
        return;
    }

    // step2. install applet
    ret = aee_applet_install(buf, "wasm", size, applet_name, 5000);
    if (ret) {
        printf("%s install success\n", applet_name);
    }
    free(buf);
}

static void
uninstall_applet(int index)
{
    int ret;
    char applet_name[64];
    snprintf(applet_name, sizeof(applet_name), "TestApplet%d", index);
    ret = aee_applet_uninstall(applet_name, "wasm", 5000);
    if (ret) {
        printf("uninstall %s success\n", applet_name);
    }
    else {
        printf("uninstall %s failed\n", applet_name);
    }
}

static void
send_request(int index)
{
    char url[64];
    int ret;
    aee_request_t req;
    const char *user_context = "label for request";
    attr_container_t *attr_obj =
        attr_container_create("Send Request to Applet");
    attr_container_set_string(&attr_obj, "String key", "Hello");
    attr_container_set_int(&attr_obj, "Int key", 1000);
    attr_container_set_int64(&attr_obj, "Int64 key", 0x77BBCCDD11223344LL);

    // specify the target wasm app
    snprintf(url, sizeof(url), "/app/TestApplet%d/url1", index);

    // not specify the target wasm app
    // snprintf(url, sizeof(url), "url1");
    aee_request_init(&req, url, COAP_PUT);
    aee_request_set_payload(&req, attr_obj,
                            attr_container_get_serialize_length(attr_obj),
                            PAYLOAD_FORMAT_ATTRIBUTE_OBJECT);
    ret = aee_request_send(&req, f_aee_response_handler, (void *)user_context,
                           10000);

    if (ret) {
        printf("send request to TestApplet1 success\n");
    }
}

static void
register_event(const char *event_path)
{
    hostclient_register_event(event_path, f_aee_event_listener);
}

static void
unregister_event(const char *event_path)
{
    hostclient_unregister_event(event_path);
}

static void
query_applets()
{
    aee_applet_list_t applet_lst;
    aee_applet_list_init(&applet_lst);
    aee_applet_list(5000, &applet_lst);
    aee_applet_list_clean(&applet_lst);
}

static char *
read_file_to_buffer(const char *filename, int *ret_size)
{
    FILE *fl = NULL;
    char *buffer = NULL;
    int file_size = 0;
    if (!(fl = fopen(filename, "rb"))) {
        printf("file open failed\n");
        return NULL;
    }

    fseek(fl, 0, SEEK_END);
    file_size = ftell(fl);

    if (file_size == 0) {
        printf("file length 0\n");
        return NULL;
    }

    if (!(buffer = (char *)malloc(file_size))) {
        fclose(fl);
        return NULL;
    }

    fseek(fl, 0, SEEK_SET);

    if (!fread(buffer, 1, file_size, fl)) {
        printf("file read failed\n");
        return NULL;
    }

    fclose(fl);
    *ret_size = file_size;
    return buffer;
}

static void
auto_test()
{
    int i;
    int interval = 1000; /* ms */
    while (1) {
        uninstall_applet(1);
        uninstall_applet(2);
        uninstall_applet(3);
        install_applet(1);
        install_applet(2);
        install_applet(3);

        for (i = 0; i < 60 * 1000 / interval; i++) {
            query_applets();
            send_request(1);
            send_request(2);
            send_request(3);
            usleep(interval * 1000);
        }
    }
}

void
exit_program()
{
    hostclient_shutdown();
    exit(0);
}

int

main()
{
    bool ret;

    // step1. host client init
    ret = hostclient_initialize(host_agent_ip, 3456);

    if (!ret) {
        printf("host client initialize failed\n");
        return -1;
    }

    do {
        int choice = print_menu_and_select();
        printf("\n");

        if (choice == 0)
            exit_program();
        if (choice <= 3)
            install_applet(choice);
        else if (choice <= 6)
            uninstall_applet(choice - 3);
        else if (choice <= 7)
            send_request(1);
        else if (choice <= 8)
            register_event("alert/overheat");
        else if (choice <= 9)
            unregister_event("alert/overheat");
        else if (choice == 10)
            query_applets();
        else if (choice == 20)
            auto_test();
    } while (1);

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started:
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or
//      Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project
//      and select the .sln file

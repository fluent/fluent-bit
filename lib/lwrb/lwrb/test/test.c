/**
 * @file test.c
 *
 * Unit tests for the lwrb library
 *
 * @author Tofik Sonono (tofik@sonono.me)
 *
 */

/*======= Includes ==========================================================*/

#include <stdint.h>
#include <stdlib.h>
#include "unity.h"
#include "lwrb/lwrb.h"

/*======= Local Macro Definitions ===========================================*/
/*======= Local function prototypes =========================================*/

void basic_read_and_write(lwrb_t* buff, uint8_t* data_to_write, size_t data_size);

/*======= Local variable declarations =======================================*/
/*======= Global function implementations ===================================*/

/* Requires a definition for Unity to compile */

void
setUp(void) { }

void
tearDown(void) { }

/*======= Tests ==============================================================*/

void
testNullInputToInit_should_fail(void) {
    uint8_t ret;
    lwrb_t buff = { 0 };
    uint8_t buff_data[1];

    ret = lwrb_init(NULL, buff_data, sizeof(buff_data));
    TEST_ASSERT_EQUAL(0, ret);

    ret = lwrb_init(&buff, NULL, sizeof(buff_data));
    TEST_ASSERT_EQUAL(0, ret);

    ret = lwrb_init(&buff, buff_data, 0);
    TEST_ASSERT_EQUAL(0, ret);

    ret = lwrb_is_ready(&buff);
    TEST_ASSERT_EQUAL(0, ret);
}

void
testNormalInputToInit_should_succeed(void) {
    uint8_t ret;
    lwrb_t buff = { 0 };
    uint8_t buff_data[1];

    ret = lwrb_init(&buff, buff_data, sizeof(buff_data));
    TEST_ASSERT_EQUAL(1, ret);

    ret = lwrb_is_ready(&buff);
    TEST_ASSERT_EQUAL(1, ret);
}

void
testAddElementsToQueueAndRead_should_succeed(void) {
    uint8_t data_to_write[] = {0, 1, 2, 3, 4, 5, 6, 7};
    lwrb_t buff = { 0 };
    basic_read_and_write(&buff, data_to_write, sizeof(data_to_write));
}

void
testAddElementsToQueueAndReadAndVerifyEmpty_should_succeed(void) {
    uint8_t data_to_write[] = {0, 1, 2, 3, 4, 5, 6, 7};
    lwrb_t buff = { 0 };
    basic_read_and_write(&buff, data_to_write, sizeof(data_to_write));

    size_t n_free_bytes = lwrb_get_free(&buff);
    TEST_ASSERT_EQUAL(sizeof(data_to_write), n_free_bytes);
}

void
testAddElementsToQueueAndReadTooSmallBuffer_should_fail(void) {
    uint8_t data_to_write[] = {0, 1, 2, 3, 4, 5, 6, 7};
    lwrb_t buff = { 0 };

    uint8_t ret;
    uint8_t buff_data[sizeof(data_to_write)];

    ret = lwrb_init(&buff, buff_data, sizeof(buff_data));
    TEST_ASSERT_EQUAL(1, ret);

    ret = lwrb_is_ready(&buff);
    TEST_ASSERT_EQUAL(1, ret);

    size_t  n_written = lwrb_write(&buff, data_to_write, sizeof(data_to_write));
    TEST_ASSERT_EQUAL(sizeof(data_to_write) - 1, n_written);
}

/*======= Main ===============================================================*/

int
main (void) {
    UNITY_BEGIN();
    RUN_TEST(testNullInputToInit_should_fail);
    RUN_TEST(testNormalInputToInit_should_succeed);
    RUN_TEST(testAddElementsToQueueAndRead_should_succeed);
    RUN_TEST(testAddElementsToQueueAndReadAndVerifyEmpty_should_succeed);
    RUN_TEST(testAddElementsToQueueAndReadTooSmallBuffer_should_fail);
    return UNITY_END();
}

/*======= Local function implementations =====================================*/

void
basic_read_and_write(lwrb_t* buff, uint8_t* data_to_write, size_t data_size) {
    uint8_t ret;
    size_t buffer_size = (sizeof(uint8_t) * data_size) + 1;
    uint8_t* buff_data = malloc(buffer_size);

    ret = lwrb_init(buff, buff_data, buffer_size);
    TEST_ASSERT_EQUAL(1, ret);

    ret = lwrb_is_ready(buff);
    TEST_ASSERT_EQUAL(1, ret);

    size_t  n_written = lwrb_write(buff, data_to_write, data_size);
    TEST_ASSERT_EQUAL(data_size, n_written);

    size_t n_bytes_in_queue = lwrb_get_full(buff);
    TEST_ASSERT_EQUAL(n_written, n_bytes_in_queue);

    uint8_t read_buffer[data_size];
    size_t n_read = lwrb_read(buff, read_buffer, n_bytes_in_queue);
    TEST_ASSERT_EQUAL(n_bytes_in_queue, n_read);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(data_to_write, read_buffer, data_size);

    free(buff_data);
}

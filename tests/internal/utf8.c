/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Tests for the incremental decoder in src/flb_utf8.c.
 *
 * The state word carries two meanings at once: how many continuation bytes are
 * still pending, and whether the sequence was rejected. These cases pin down
 * what a streaming caller sees after ill-formed input, which is where that
 * sharing used to show: every later byte kept being rejected instead of resuming
 * after the bad subpart, and a stale partial codepoint could be completed by an
 * unrelated continuation byte into a value those bytes never encoded.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utf8.h>

#include "flb_tests_internal.h"

/* Marks the end of a step list; not a valid classification value */
#define STEP_END 0xFF

struct decode_step {
    unsigned char byte;
    uint32_t expected;
};

static void check_steps(const struct decode_step *steps)
{
    size_t index = 0;
    uint32_t codepoint = 0;
    uint32_t ret;
    uint32_t state = FLB_UTF8_ACCEPT;

    while (steps[index].expected != STEP_END) {
        ret = flb_utf8_decode(&state, &codepoint, steps[index].byte);

        if (!TEST_CHECK(ret == steps[index].expected)) {
            TEST_MSG("step %zu byte 0x%02x: expected %u got %u",
                     index, steps[index].byte, steps[index].expected, ret);
        }

        if (ret == FLB_UTF8_ACCEPT) {
            TEST_CHECK(state == FLB_UTF8_ACCEPT);
            if (steps[index].byte <= 0x7F) {
                TEST_CHECK(codepoint == steps[index].byte);
            }
        }

        index++;
    }
}

void test_decode_valid_sequences()
{
    uint32_t codepoint = 0;
    uint32_t ret;
    uint32_t state = FLB_UTF8_ACCEPT;

    /* ASCII */
    ret = flb_utf8_decode(&state, &codepoint, 'A');
    TEST_CHECK(ret == FLB_UTF8_ACCEPT);
    TEST_CHECK(codepoint == 0x41);

    /* U+00E9: two bytes */
    state = FLB_UTF8_ACCEPT;
    ret = flb_utf8_decode(&state, &codepoint, 0xC3);
    TEST_CHECK(ret == FLB_UTF8_CONTINUE);
    ret = flb_utf8_decode(&state, &codepoint, 0xA9);
    TEST_CHECK(ret == FLB_UTF8_ACCEPT);
    TEST_CHECK(codepoint == 0xE9);

    /* U+20AC: three bytes */
    state = FLB_UTF8_ACCEPT;
    ret = flb_utf8_decode(&state, &codepoint, 0xE2);
    TEST_CHECK(ret == FLB_UTF8_CONTINUE);
    ret = flb_utf8_decode(&state, &codepoint, 0x82);
    TEST_CHECK(ret == FLB_UTF8_CONTINUE);
    ret = flb_utf8_decode(&state, &codepoint, 0xAC);
    TEST_CHECK(ret == FLB_UTF8_ACCEPT);
    TEST_CHECK(codepoint == 0x20AC);

    /* U+1F600: four bytes */
    state = FLB_UTF8_ACCEPT;
    ret = flb_utf8_decode(&state, &codepoint, 0xF0);
    TEST_CHECK(ret == FLB_UTF8_CONTINUE);
    ret = flb_utf8_decode(&state, &codepoint, 0x9F);
    TEST_CHECK(ret == FLB_UTF8_CONTINUE);
    ret = flb_utf8_decode(&state, &codepoint, 0x98);
    TEST_CHECK(ret == FLB_UTF8_CONTINUE);
    ret = flb_utf8_decode(&state, &codepoint, 0x80);
    TEST_CHECK(ret == FLB_UTF8_ACCEPT);
    TEST_CHECK(codepoint == 0x1F600);
}

/*
 * A rejected byte must not poison the rest of the stream: the following valid
 * characters still decode.
 */
void test_resumes_after_invalid_lead()
{
    const struct decode_step steps[] = {
        {0xC0, FLB_UTF8_REJECT},   /* never a valid lead byte */
        {'A',  FLB_UTF8_ACCEPT},
        {'B',  FLB_UTF8_ACCEPT},
        {0x00, STEP_END}
    };

    check_steps(steps);
}

/*
 * Same for an invalid continuation byte. The sequence restarts at the next lead
 * byte, so U+00E9 must come out as 0xE9 and not as some value assembled from
 * the abandoned 0xE2 prefix.
 */
void test_resumes_after_invalid_continuation()
{
    size_t index = 0;
    uint32_t codepoint = 0;
    uint32_t ret;
    uint32_t state = FLB_UTF8_ACCEPT;
    const struct decode_step steps[] = {
        {0xE2, FLB_UTF8_CONTINUE},
        {'X',  FLB_UTF8_REJECT},   /* not a continuation byte */
        {0xC3, FLB_UTF8_CONTINUE},
        {0xA9, FLB_UTF8_ACCEPT},
        {0x00, STEP_END}
    };

    while (steps[index].expected != STEP_END) {
        ret = flb_utf8_decode(&state, &codepoint, steps[index].byte);

        if (!TEST_CHECK(ret == steps[index].expected)) {
            TEST_MSG("step %zu byte 0x%02x: expected %u got %u",
                     index, steps[index].byte, steps[index].expected, ret);
        }

        index++;
    }

    TEST_CHECK(codepoint == 0xE9);
}

/*
 * Callers that inspect the state instead of the return value must still see
 * failure right after a rejection.
 */
void test_state_not_accept_after_reject()
{
    uint32_t codepoint = 0;
    uint32_t ret;
    uint32_t state = FLB_UTF8_ACCEPT;

    ret = flb_utf8_decode(&state, &codepoint, 0xFF);
    TEST_CHECK(ret == FLB_UTF8_REJECT);
    TEST_CHECK(state != FLB_UTF8_ACCEPT);
}

void test_rejects_overlong_and_out_of_range()
{
    const struct decode_step overlong_two[] = {
        {0xC0, FLB_UTF8_REJECT},
        {0x80, STEP_END}
    };
    const struct decode_step overlong_three[] = {
        {0xE0, FLB_UTF8_CONTINUE},
        {0x80, FLB_UTF8_REJECT},   /* U+0000 needs no three bytes */
        {0x80, STEP_END}
    };
    const struct decode_step overlong_four[] = {
        {0xF0, FLB_UTF8_CONTINUE},
        {0x80, FLB_UTF8_REJECT},   /* U+0000 needs no four bytes */
        {0x80, STEP_END}
    };
    const struct decode_step surrogate[] = {
        {0xED, FLB_UTF8_CONTINUE},
        {0xA0, FLB_UTF8_CONTINUE},
        {0x80, FLB_UTF8_REJECT},   /* U+D800 is not a character */
        {0x00, STEP_END}
    };
    const struct decode_step out_of_range[] = {
        {0xF4, FLB_UTF8_CONTINUE},
        {0x90, FLB_UTF8_CONTINUE},
        {0x80, FLB_UTF8_CONTINUE},
        {0x80, FLB_UTF8_REJECT},   /* U+110000 exceeds the range */
        {0x00, STEP_END}
    };

    check_steps(overlong_two);
    check_steps(overlong_three);
    check_steps(overlong_four);
    check_steps(surrogate);
    check_steps(out_of_range);
}

TEST_LIST = {
    { "decode_valid_sequences", test_decode_valid_sequences },
    { "resumes_after_invalid_lead", test_resumes_after_invalid_lead },
    { "resumes_after_invalid_continuation", test_resumes_after_invalid_continuation },
    { "state_not_accept_after_reject", test_state_not_accept_after_reject },
    { "rejects_overlong_and_out_of_range", test_rejects_overlong_and_out_of_range },
    { 0 }
};

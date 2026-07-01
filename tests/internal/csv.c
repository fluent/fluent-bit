#include <fluent-bit/flb_csv.h>
#include <fluent-bit/flb_sds.h>
#include <string.h>

#include "flb_tests_internal.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define row_count 3
#define col_count 4

char data[] =
    "r0c1,,,\r"
    ",r1c2,\"\",\"r1three\nlines\nfield\"\r\n"
    "r2c1,r2c2,\"\"\"r2c\n3\n\",\"r2three\nlines\nfield\"\"\"\n";

char *parse_expected[row_count][col_count] = {
    { "r0c1", "", "", "" },
    { "", "r1c2", "", "r1three\nlines\nfield" },
    { "r2c1", "r2c2", "\"r2c\n3\n", "r2three\nlines\nfield\"" },
};

char *split_expected[row_count] = {
    "r0c1,,,\r",
    ",r1c2,\"\",\"r1three\nlines\nfield\"\r\n",
    "r2c1,r2c2,\"\"\"r2c\n3\n\",\"r2three\nlines\nfield\"\"\"\n",
};

struct parse_state {
    char **parsed;
    size_t current_row;
    size_t current_col;
};

static void field_parsed(void *data, const char *field, size_t field_len)
{
    struct parse_state *state = data;
    size_t col = state->current_col;
    size_t row = state->current_row;
    char *fdup = strndup(field, field_len);
    state->parsed[row * col_count + col] = fdup;
    state->current_col++;
}

static char **parse_data_step(int step)
{
    int i;
    size_t len = sizeof(data);
    struct parse_state state;
    char *bufptr;
    struct flb_csv_state csv_state;
    size_t field_count;
    state.parsed = malloc(sizeof *state.parsed * row_count * col_count);
    state.current_row = 0;
    state.current_col = 0;
    flb_csv_init(&csv_state, field_parsed, &state);
    bufptr = data;
    for (i = 0; i < sizeof(data);) {
        int ret;
        size_t bl = MIN(len - i, step);
        ret = flb_csv_parse_record(&csv_state, &bufptr, &bl, &field_count);
        i = bufptr - data;
        if (ret == FLB_CSV_SUCCESS) {
            TEST_CHECK(field_count == 4);
            state.current_row++;
            state.current_col = 0;
        }
        else if (ret == FLB_CSV_EOF) {
            continue;
        }
        else {
            abort();
        };
    }
    flb_csv_destroy(&csv_state);
    return state.parsed;
}

static void check_parse_result(char **result)
{
    int row, col;

    for (row = 0; row < row_count; row++) {
        for (col = 0; col < col_count; col++) {
            char *res = result[row * col_count + col];
            TEST_CHECK(strcmp(res, parse_expected[row][col]) == 0);
            TEST_MSG("Mismatch on row %d, col %d", row, col);
            TEST_MSG("Expected: %s", parse_expected[row][col]);
            TEST_MSG("Result:   %s", result[row * col_count + col]);
            free(res);
        }
    }

    free(result);
}

static void check_split_result(char **result)
{
    int row;

    for (row = 0; row < row_count; row++) {
        char *res = result[row];
        TEST_CHECK(strcmp(res, split_expected[row]) == 0);
        TEST_MSG("Mismatch on row %d", row);
        TEST_MSG("Expected: %s", split_expected[row]);
        TEST_MSG("Result:   %s", result[row]);
        free(res);
    }

    free(result);
}

static char **split_rows_step(int step)
{
    int i;
    size_t len = sizeof(data);
    char *bufptr;
    char *row_start;
    size_t current_row = 0;
    char **result = malloc(sizeof *result * row_count);
    struct flb_csv_state csv_state;
    flb_csv_init(&csv_state, NULL, NULL);
    bufptr = data;
    row_start = data;
    size_t field_count;
    for (i = 0; i < len;) {
        int ret;
        size_t bl = MIN(len - i, step);
        ret = flb_csv_parse_record(&csv_state, &bufptr, &bl, &field_count);
        i = bufptr - data;
        if (ret == FLB_CSV_SUCCESS) {
            TEST_CHECK(field_count == 4);
            result[current_row] = strndup(row_start, bufptr - row_start);
            row_start = bufptr;
            current_row++;
        }
        else if (ret == FLB_CSV_EOF) {
            continue;
        } else {
            abort();
        };
    }
    flb_csv_destroy(&csv_state);
    return result;
}

static void test_basic()
{
    int step;
    for (step = 1; step <= sizeof(data); step++) {
        check_parse_result(parse_data_step(step));
    }
}

static void test_split_lines()
{
    int step;
    for (step = 1; step <= sizeof(data); step++) {
        check_split_result(split_rows_step(step));
    }
}

TEST_LIST = {
    { "basic" , test_basic},
    { "split_lines" , test_split_lines},
    { 0 }
};

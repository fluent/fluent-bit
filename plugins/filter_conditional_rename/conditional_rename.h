#ifndef FLB_FILTER_CONDITIONAL_RENAME_H
#define FLB_FILTER_CONDITIONAL_RENAME_H

struct filter_conditional_rename_ctx
{
    char *if_equal_key;
    int   if_equal_key_len;
    char *if_equal_val;
    int   if_equal_val_len;
    char *rename_field;
    int   rename_field_len;
    char *rename_renamed_field;
    int   rename_renamed_field_len;
};

#endif
/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_hash_table.h>

#include "flb_tests_internal.h"

struct map {
    char *key;
    char *val;
};

struct map entries[] = {
    {"key_0", "val_0"},
    {"key_1", "val_1"}, {"key_2", "val_2"}, {"key_3", "val_3"},
    {"key_4", "val_4"}, {"key_5", "val_5"}, {"key_6", "val_6"},
    {"key_7", "val_7"}, {"key_8", "val_8"}, {"key_9", "val_9"},
    {"key_10", "val_10"}, {"key_11", "val_11"}, {"key_12", "val_12"},
    {"key_13", "val_13"}, {"key_14", "val_14"}, {"key_15", "val_15"},
    {"key_16", "val_16"}, {"key_17", "val_17"}, {"key_18", "val_18"},
    {"key_19", "val_19"}, {"key_20", "val_20"}, {"key_21", "val_21"},
    {"key_22", "val_22"}, {"key_23", "val_23"}, {"key_24", "val_24"},
    {"key_25", "val_25"}, {"key_26", "val_26"}, {"key_27", "val_27"},
    {"key_28", "val_28"}, {"key_29", "val_29"}, {"key_30", "val_30"},
    {"key_31", "val_31"}, {"key_32", "val_32"}, {"key_33", "val_33"},
    {"key_34", "val_34"}, {"key_35", "val_35"}, {"key_36", "val_36"},
    {"key_37", "val_37"}, {"key_38", "val_38"}, {"key_39", "val_39"},
    {"key_40", "val_40"}, {"key_41", "val_41"}, {"key_42", "val_42"},
    {"key_43", "val_43"}, {"key_44", "val_44"}, {"key_45", "val_45"},
    {"key_46", "val_46"}, {"key_47", "val_47"}, {"key_48", "val_48"},
    {"key_49", "val_49"}, {"key_50", "val_50"}, {"key_51", "val_51"},
    {"key_52", "val_52"}, {"key_53", "val_53"}, {"key_54", "val_54"},
    {"key_55", "val_55"}, {"key_56", "val_56"}, {"key_57", "val_57"},
    {"key_58", "val_58"}, {"key_59", "val_59"}, {"key_60", "val_60"},
    {"key_61", "val_61"}, {"key_62", "val_62"}, {"key_63", "val_63"},
    {"key_64", "val_64"}, {"key_65", "val_65"}, {"key_66", "val_66"},
    {"key_67", "val_67"}, {"key_68", "val_68"}, {"key_69", "val_69"},
    {"key_70", "val_70"}, {"key_71", "val_71"}, {"key_72", "val_72"},
    {"key_73", "val_73"}, {"key_74", "val_74"}, {"key_75", "val_75"},
    {"key_76", "val_76"}, {"key_77", "val_77"}, {"key_78", "val_78"},
    {"key_79", "val_79"}, {"key_80", "val_80"}, {"key_81", "val_81"},
    {"key_82", "val_82"}, {"key_83", "val_83"}, {"key_84", "val_84"},
    {"key_85", "val_85"}, {"key_86", "val_86"}, {"key_87", "val_87"},
    {"key_88", "val_88"}, {"key_89", "val_89"}, {"key_90", "val_90"},
    {"key_91", "val_91"}, {"key_92", "val_92"}, {"key_93", "val_93"},
    {"key_94", "val_94"}, {"key_95", "val_95"}, {"key_96", "val_96"},
    {"key_97", "val_97"}, {"key_98", "val_98"}, {"key_99", "val_99"},

    /* override some values */
    {"key_67", "val_AA"}, {"key_68", "val_BB"}, {"key_69", "val_CC"},

};

static int ht_add(struct flb_hash_table *ht, char *key, char *val)
{
  int id;
  int idn;
  int klen;
  int vlen;
  char *out_buf;
  size_t out_size;

  klen = strlen(key);
  vlen = strlen(val);

  /* Insert the key value */
  id = flb_hash_table_add(ht, key, klen, val, vlen);
  TEST_CHECK(id >=0);

  /* Retrieve the value of the recently added key */
  idn = flb_hash_table_get(ht, key, klen, (void *) &out_buf, &out_size);
  TEST_CHECK(idn == id);
  TEST_CHECK(strcmp(out_buf, val) == 0);

  return id;
}

void test_create_zero()
{
    struct flb_hash_table *ht;

    ht  = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 0, -1);
    TEST_CHECK(ht == NULL);
}

/* bug 355 */
void test_single()
{
    int ret;
    const char *out_buf;
    size_t out_size;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1, -1);
    TEST_CHECK(ht != NULL);

    ret = ht_add(ht, "key", "value");
    TEST_CHECK(ret != -1);

    ret = flb_hash_table_get(ht, "key", 3, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "NOT", 3, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == -1);

    flb_hash_table_destroy(ht);
}

void test_small_table()
{
    int i;
    struct map *m;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 8, -1);
    TEST_CHECK(ht != NULL);

    for (i = 0; i < sizeof(entries) / sizeof(struct map); i++) {
        m = &entries[i];
        ht_add(ht, m->key, m->val);
    }

    flb_hash_table_destroy(ht);
}

void test_medium_table()
{
    int i;
    struct map *m;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 8, -1);
    TEST_CHECK(ht != NULL);

    for (i = 0; i < sizeof(entries) / sizeof(struct map); i++) {
        m = &entries[i];
        ht_add(ht, m->key, m->val);
    }

    flb_hash_table_destroy(ht);
}

void test_chaining()
{
    int i;
    int inserts = 0;
    int count;
    int chains = 0;
    struct map *m;
    struct mk_list *head;
    struct flb_hash_table_chain *table;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 8, -1);
    TEST_CHECK(ht != NULL);

    for (i = 0; i < 8; i++) {
        m = &entries[i];
        ht_add(ht, m->key, m->val);
        inserts++;
    }

    for (i = 0; i < ht->size; i++) {
        table = &ht->table[i];
        count = 0;
        mk_list_foreach(head, &table->chains) {
            count++;
        }
        TEST_CHECK(count == table->count);

        if (count > 0) {
            chains++;
        }
    }

    /* Tests diff between total, new minus 3 overrides */
    TEST_CHECK(chains == inserts - 3);
    flb_hash_table_destroy(ht);
}

void test_delete_all()
{
    int i;
    int ret;
    int count;
    int not_found = 0;
    int total = 0;
    struct map *m;
    struct flb_hash_table_chain *table;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 8, -1);
    TEST_CHECK(ht != NULL);

    total = sizeof(entries) / sizeof(struct map);
    for (i = 0; i < total; i++) {
        m = &entries[i];
        ht_add(ht, m->key, m->val);
    }

    for (i = total - 1; i >= 0; i--) {
        m = &entries[i];
        ret = flb_hash_table_del(ht, m->key);
        if (ret == -1) {
            not_found++;
        }
    }

    count = 0;
    for (i = 0; i < ht->size; i++) {
        table = &ht->table[i];
        count += table->count;
    }

    TEST_CHECK(count == 0);
    flb_hash_table_destroy(ht);

    fprintf(stderr, "[hash table] total=%i not_found=%i\n", total, not_found);
}

void test_random_eviction()
{
    int ret;
    const char *out_buf;
    size_t out_size;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_RANDOM, 8, 1);
    TEST_CHECK(ht != NULL);

    ret = ht_add(ht, "key1", "value1");
    TEST_CHECK(ret != -1);

    ret = ht_add(ht, "key2", "value2");
    TEST_CHECK(ret != -1);

    ret = flb_hash_table_get(ht, "key1", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == -1);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    flb_hash_table_destroy(ht);
}

void test_less_used_eviction()
{
    int ret;
    const char *out_buf;
    size_t out_size;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_LESS_USED, 8, 2);
    TEST_CHECK(ht != NULL);

    ret = ht_add(ht, "key1", "value1");
    TEST_CHECK(ret != -1);

    ret = ht_add(ht, "key2", "value2");
    TEST_CHECK(ret != -1);

    ret = flb_hash_table_get(ht, "key1", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = ht_add(ht, "key3", "value3");
    TEST_CHECK(ret != -1);

    ret = flb_hash_table_get(ht, "key3", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key1", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == -1);

    flb_hash_table_destroy(ht);
}

void test_older_eviction()
{
    int ret;
    const char *out_buf;
    size_t out_size;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_OLDER, 8, 2);
    TEST_CHECK(ht != NULL);

    ret = ht_add(ht, "key2", "value2");
    TEST_CHECK(ret != -1);

    ret = ht_add(ht, "key1", "value1");
    TEST_CHECK(ret != -1);

    ret = flb_hash_table_get(ht, "key1", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = ht_add(ht, "key3", "value3");
    TEST_CHECK(ret != -1);

    ret = flb_hash_table_get(ht, "key3", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == -1);

    ret = flb_hash_table_get(ht, "key1", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);

    flb_hash_table_destroy(ht);
}

void test_pointer()
{
    int ret;
    const char *out_buf;
    size_t out_size;
    struct flb_hash_table *ht;

    char *val1 = "val1";
    char *val2 = "val2";

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 512, 0);
    TEST_CHECK(ht != NULL);

    ret = flb_hash_table_add(ht, "key1", 4, (void *) val1, 0);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_add(ht, "key2", 4, (void *) val2, 0);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_get(ht, "key2", 4, (void *) &out_buf, &out_size);
    TEST_CHECK(ret >= 0);
    TEST_CHECK((void *) out_buf == (void *) val2);

    out_buf = flb_hash_table_get_ptr(ht, "key2", 4);
    TEST_CHECK((void *) out_buf == (void *) val2);

    ret = flb_hash_table_del_ptr(ht, "key2", 4, (void *) out_buf);
    TEST_CHECK(ret == 0);

    TEST_CHECK(ht->total_count == 1);
    flb_hash_table_destroy(ht);
}

void test_hash_exists()
{
    int i;
    int id;
    int ret;
    int len;
    struct map *m;
    uint64_t hash;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1000, 0);
    TEST_CHECK(ht != NULL);

    for (i = 0; i < sizeof(entries) / sizeof(struct map); i++) {
        m = &entries[i];
        id = ht_add(ht, m->key, m->val);
        TEST_CHECK(id >= 0);

        len = strlen(m->key);
        hash = cfl_hash_64bits(m->key, len);

        ret = flb_hash_table_exists(ht, hash);
        TEST_CHECK(ret == FLB_TRUE);
    }

    for (i = 0; i < sizeof(entries) / sizeof(struct map); i++) {
        m = &entries[i];

        /* get hash */
        len = strlen(m->key);
        hash = cfl_hash_64bits(m->key, len);

        /* delete */
        ret = flb_hash_table_del(ht, m->key);

        ret = flb_hash_table_exists(ht, hash);
        TEST_CHECK(ret == FLB_FALSE);;
    }

    flb_hash_table_destroy(ht);
}

/* Ensure long keys hashed case-insensitively do not leak memory */
void test_case_insensitive_long_key()
{
    int i;
    int ret;
    char key[128];
    struct flb_hash_table *ht;

    memset(key, 'A', sizeof(key) - 1);
    key[sizeof(key) - 1] = '\0';

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 8, -1);
    TEST_CHECK(ht != NULL);

    flb_hash_table_set_case_sensitivity(ht, FLB_FALSE);

    for (i = 0; i < 10; i++) {
        ret = flb_hash_table_add(ht, key, strlen(key), "val", 3);
        TEST_CHECK(ret >= 0);
        ret = flb_hash_table_del(ht, key);
        TEST_CHECK(ret == 0);
    }

    flb_hash_table_destroy(ht);
}

/* Deleting a short key should not remove a longer key with the same prefix */
void test_delete_shared_prefix()
{
    int ret;
    const char *out;
    size_t out_size;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 8, -1);
    TEST_CHECK(ht != NULL);

    ret = flb_hash_table_add(ht, "prefix", 6, "short", 5);
    TEST_CHECK(ret >= 0);
    ret = flb_hash_table_add(ht, "prefix-long", 11, "long", 4);
    TEST_CHECK(ret >= 0);

    ret = flb_hash_table_del(ht, "prefix");
    TEST_CHECK(ret == 0);

    ret = flb_hash_table_get(ht, "prefix-long", 11, (void *)&out, &out_size);
    TEST_CHECK(ret >= 0);
    TEST_CHECK(out_size == 4);
    TEST_CHECK(strncmp(out, "long", out_size) == 0);

    ret = flb_hash_table_get(ht, "prefix", 6, (void *)&out, &out_size);
    TEST_CHECK(ret == -1);

    flb_hash_table_destroy(ht);
}

TEST_LIST = {
    { "zero_size", test_create_zero },
    { "single",    test_single },
    { "small_table", test_small_table },
    { "medium_table", test_medium_table },
    { "chaining_count", test_chaining },
    { "delete_all", test_delete_all },
    { "random_eviction", test_random_eviction },
    { "less_used_eviction", test_less_used_eviction },
    { "older_eviction", test_older_eviction },
    { "pointer", test_pointer },
    { "hash_exists", test_hash_exists},
    { "case_insensitive_long_key", test_case_insensitive_long_key },
    { "delete_shared_prefix", test_delete_shared_prefix },
    { 0 }
};

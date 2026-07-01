/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gtest/gtest.h"
#include "bh_platform.h"
#include <fstream>
#include "test_helper.h"
#include "aot_export.h"

class CustomSectionTest : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp() {}

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

  public:
    WAMRRuntimeRAII<1 * 1024 * 1024> runtime;
};

TEST_F(CustomSectionTest, get_custom_section_from_wasm_module_t)
{
    uint32_t length, len_from_aot;
    const uint8_t *content, *content_from_aot;
    std::ifstream wasm_file("wasm-apps/app.wasm", std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(wasm_file),
                                      {});
    {
        WAMRModule module(buffer.data(), buffer.size());
        aot_comp_data_t comp_data = NULL;
        aot_comp_context_t comp_ctx = NULL;
        std::vector<const char *> sections_to_emit{
            "name",
            ".debug_info",
            ".debug_abbrev",
            /* skip ".debug_line" section in AoT module */
            ".debug_str",
            "producers",
        };

        AOTCompOption option = { 0 };
        option.custom_sections = (char **)sections_to_emit.data();
        option.custom_sections_count = 5;

        {
            /* Compile an AoT module */
            comp_data = aot_create_comp_data(module.get(), NULL, false);
            EXPECT_NE(comp_data, nullptr);

            comp_ctx = aot_create_comp_context(comp_data, &option);
            EXPECT_NE(comp_ctx, nullptr);

            EXPECT_TRUE(aot_compile_wasm(comp_ctx));

            EXPECT_TRUE(aot_emit_aot_file(comp_ctx, comp_data, "temp.aot"));
        }

        std::ifstream aot_file("temp.aot", std::ios::binary);
        std::vector<unsigned char> aot_buffer(
            std::istreambuf_iterator<char>(aot_file), {});
        WAMRModule aot_module(aot_buffer.data(), aot_buffer.size());

        /* name */
        content =
            wasm_runtime_get_custom_section(module.get(), "name", &length);
        EXPECT_NE(content, nullptr);
        EXPECT_GT(length, 0);

        /* TODO: aot_emit_name_section don't 
           EMIT_U32(AOT_CUSTOM_SECTION_RAW);*
           EMIT_STR("name");
           but instead
           EMIT_U32(AOT_CUSTOM_SECTION_NAME);
           can't use get_custom_section to get it
        */
        // content_from_aot = wasm_runtime_get_custom_section(
        //     aot_module.get(), "name", &len_from_aot);
        // EXPECT_NE(content_from_aot, nullptr);
        // EXPECT_EQ(len_from_aot, length);
        // EXPECT_EQ(memcmp(content_from_aot, content, length), 0);

        /* .debug_info */
        content = wasm_runtime_get_custom_section(module.get(), ".debug_info",
                                                  &length);
        EXPECT_NE(content, nullptr);
        EXPECT_GT(length, 0);

        content_from_aot = wasm_runtime_get_custom_section(
            aot_module.get(), ".debug_info", &len_from_aot);
        EXPECT_NE(content_from_aot, nullptr);
        EXPECT_EQ(len_from_aot, length);
        EXPECT_EQ(memcmp(content_from_aot, content, length), 0);

        /* .debug_abbrev */
        content = wasm_runtime_get_custom_section(module.get(), ".debug_abbrev",
                                                  &length);
        EXPECT_NE(content, nullptr);
        EXPECT_GT(length, 0);

        content_from_aot = wasm_runtime_get_custom_section(
            aot_module.get(), ".debug_abbrev", &len_from_aot);
        EXPECT_NE(content_from_aot, nullptr);
        EXPECT_EQ(len_from_aot, length);
        EXPECT_EQ(memcmp(content_from_aot, content, length), 0);

        /* .debug_line */
        content = wasm_runtime_get_custom_section(module.get(), ".debug_line",
                                                  &length);
        EXPECT_NE(content, nullptr);
        EXPECT_GT(length, 0);

        content_from_aot = wasm_runtime_get_custom_section(
            aot_module.get(), ".debug_line", &len_from_aot);
        EXPECT_EQ(content_from_aot, nullptr);

        /* .debug_str */
        content = wasm_runtime_get_custom_section(module.get(), ".debug_str",
                                                  &length);
        EXPECT_NE(content, nullptr);
        EXPECT_GT(length, 0);

        content_from_aot = wasm_runtime_get_custom_section(
            aot_module.get(), ".debug_str", &len_from_aot);
        EXPECT_NE(content_from_aot, nullptr);
        EXPECT_EQ(len_from_aot, length);
        EXPECT_EQ(memcmp(content_from_aot, content, length), 0);

        /* producers */
        content =
            wasm_runtime_get_custom_section(module.get(), "producers", &length);
        EXPECT_NE(content, nullptr);
        EXPECT_GT(length, 0);

        content_from_aot = wasm_runtime_get_custom_section(
            aot_module.get(), "producers", &len_from_aot);
        EXPECT_NE(content_from_aot, nullptr);
        EXPECT_EQ(len_from_aot, length);
        EXPECT_EQ(memcmp(content_from_aot, content, length), 0);

        /* Not exist */
        content = wasm_runtime_get_custom_section(module.get(), "producers1",
                                                  &length);
        EXPECT_EQ(content, nullptr);

        content_from_aot = wasm_runtime_get_custom_section(
            aot_module.get(), "producers1", &len_from_aot);
        EXPECT_EQ(content_from_aot, nullptr);
    }
}

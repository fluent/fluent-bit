/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#pragma once

#include "wasm_export.h"
#include "gtest/gtest.h"

#include <iostream>
#include <memory>
#include <fstream>

template<int Size = 512 * 1024>
class WAMRRuntimeRAII
{
  private:
    char global_heap_buf[Size];
    RuntimeInitArgs init_args;

  public:
    WAMRRuntimeRAII()
    {
        memset(&init_args, 0, sizeof(RuntimeInitArgs));

        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

        wasm_runtime_full_init(&init_args);
    }

    ~WAMRRuntimeRAII() { wasm_runtime_destroy(); }
};

class WAMRModule
{
  private:
    wasm_module_t module_;

  public:
    WAMRModule(uint8_t *buffer, uint32_t size)
    {
        module_ = wasm_runtime_load(buffer, size, NULL, 0);
    }

    ~WAMRModule() { wasm_runtime_unload(module_); }

    wasm_module_t get() const { return module_; }
};

class WAMRInstance
{
  private:
    wasm_module_inst_t module_inst_;

  public:
    WAMRInstance(WAMRModule &module, uint32_t stack_size = 8192,
                 uint32_t heap_size = 8192)
    {
        module_inst_ = wasm_runtime_instantiate(module.get(), stack_size,
                                                heap_size, NULL, 0);
    }

    ~WAMRInstance() { wasm_runtime_deinstantiate(module_inst_); }

    wasm_module_inst_t get() const { return module_inst_; }
};

class WAMRExecEnv
{
  private:
    wasm_exec_env_t exec_env_;

  public:
    WAMRExecEnv(WAMRInstance &instance, uint32_t stack_size = 8192)
    {
        exec_env_ = wasm_runtime_create_exec_env(instance.get(), stack_size);
    }

    ~WAMRExecEnv() { wasm_runtime_destroy_exec_env(exec_env_); }

    wasm_exec_env_t get() const { return exec_env_; }
    wasm_module_inst_t get_inst() const
    {
        return wasm_runtime_get_module_inst(exec_env_);
    }
};

static uint8_t dummy_wasm_buffer[] = {
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00,
    0x02, 0x06, 0x08, 0x01, 0x7F, 0x01, 0x41, 0x80, 0x88, 0x04, 0x0B, 0x07,
    0x0A, 0x01, 0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00, 0x00,
    0x19, 0x04, 0x6E, 0x61, 0x6D, 0x65, 0x07, 0x12, 0x01, 0x00, 0x0F, 0x5F,
    0x5F, 0x73, 0x74, 0x61, 0x63, 0x6B, 0x5F, 0x70, 0x6F, 0x69, 0x6E, 0x74,
    0x65, 0x72, 0x00, 0x76, 0x09, 0x70, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x65,
    0x72, 0x73, 0x01, 0x0C, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x65,
    0x64, 0x2D, 0x62, 0x79, 0x01, 0x05, 0x63, 0x6C, 0x61, 0x6E, 0x67, 0x56,
    0x31, 0x33, 0x2E, 0x30, 0x2E, 0x30, 0x20, 0x28, 0x68, 0x74, 0x74, 0x70,
    0x73, 0x3A, 0x2F, 0x2F, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2E, 0x63,
    0x6F, 0x6D, 0x2F, 0x6C, 0x6C, 0x76, 0x6D, 0x2F, 0x6C, 0x6C, 0x76, 0x6D,
    0x2D, 0x70, 0x72, 0x6F, 0x6A, 0x65, 0x63, 0x74, 0x20, 0x66, 0x64, 0x31,
    0x64, 0x38, 0x63, 0x32, 0x66, 0x30, 0x34, 0x64, 0x64, 0x65, 0x32, 0x33,
    0x62, 0x65, 0x65, 0x30, 0x66, 0x62, 0x33, 0x61, 0x37, 0x64, 0x30, 0x36,
    0x39, 0x61, 0x39, 0x62, 0x31, 0x30, 0x34, 0x36, 0x64, 0x61, 0x39, 0x37,
    0x39, 0x29
};

class DummyExecEnv
{
  private:
    std::shared_ptr<WAMRExecEnv> dummy_exec_env_;
    std::shared_ptr<WAMRInstance> inst_;
    std::shared_ptr<WAMRModule> mod_;
    std::vector<uint8_t> my_wasm_buffer;

  private:
    void construct(uint8_t *buf, uint32_t len)
    {
        std::vector<uint8_t> buffer(buf, buf + len);
        my_wasm_buffer = buffer;

        mod_ = std::make_shared<WAMRModule>(my_wasm_buffer.data(),
                                            my_wasm_buffer.size());
        EXPECT_NE(mod_.get(), nullptr);
        inst_ = std::make_shared<WAMRInstance>(*mod_);
        EXPECT_NE(inst_.get(), nullptr);
        dummy_exec_env_ = std::make_shared<WAMRExecEnv>(*inst_);
        EXPECT_NE(dummy_exec_env_.get(), nullptr);
    }

  public:
    DummyExecEnv() { construct(dummy_wasm_buffer, sizeof(dummy_wasm_buffer)); }

    DummyExecEnv(uint8_t *buf, uint32_t len) { construct(buf, len); }

    DummyExecEnv(std::string filename)
    {
        std::ifstream wasm_file(filename, std::ios::binary);
        std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(wasm_file),
                                    {});

        construct(buffer.data(), buffer.size());
    }

    ~DummyExecEnv() {}

    wasm_exec_env_t get() const { return dummy_exec_env_->get(); }

    void *app_to_native(uint32_t app_addr) const
    {
        return wasm_runtime_addr_app_to_native(inst_->get(), app_addr);
    }

    uint32_t native_to_app(void *ptr) const
    {
        return wasm_runtime_addr_native_to_app(inst_->get(), ptr);
    }

    const char *get_exception() const
    {
        return wasm_runtime_get_exception(inst_->get());
    }

    void set_exception(std::string str) const
    {
        wasm_runtime_set_exception(inst_->get(), str.c_str());
    }

    void clear_exception() const { wasm_runtime_clear_exception(inst_->get()); }

    bool execute(const char *func_name, uint32_t argc, uint32_t argv[])
    {
        wasm_function_inst_t func;

        if (!(func = wasm_runtime_lookup_function(inst_->get(), func_name))) {
            return false;
        }

        return wasm_runtime_call_wasm(dummy_exec_env_->get(), func, argc, argv);
    }
};

class WAMRVaList
{
  private:
    void *buffer_;
    uint32_t current_loc_;
    uint32_t capacity_;
    wasm_exec_env_t exec_env_;

    void _append(void *ptr, uint32_t size)
    {
        if (current_loc_ + size >= capacity_) {
            capacity_ *= 2;
            buffer_ = realloc(buffer_, capacity_);
            ASSERT_NE(buffer_, nullptr);
        }

        memcpy((void *)((uintptr_t)buffer_ + current_loc_), ptr, size);
        current_loc_ += size;
    }

  public:
    explicit WAMRVaList(wasm_exec_env_t exec_env)
      : exec_env_(exec_env)
    {
        capacity_ = 64;
        buffer_ = malloc(capacity_);
        EXPECT_NE(buffer_, nullptr);
        current_loc_ = 0;
    }

    ~WAMRVaList()
    {
        current_loc_ = 0;
        free(buffer_);
    }

    template<typename T>
    void add(T arg)
    {
        if (std::is_floating_point<T>::value) {
            /* float data should be 8 bytes aligned */
            current_loc_ = ((current_loc_ + 7) & ~7);
            _append(&arg, sizeof(T));
        }
        else if (std::is_integral<T>::value) {
            if (sizeof(T) > 4) {
                current_loc_ = ((current_loc_ + 7) & ~7);
            }
            _append(&arg, sizeof(T));
        }
    }

    void add(std::string arg)
    {
        void *native_addr;
        auto inst = wasm_runtime_get_module_inst(exec_env_);
        uint32_t addr =
            wasm_runtime_module_malloc(inst, arg.size() + 1, &native_addr);
        ASSERT_NE(addr, 0);
        memcpy(native_addr, arg.data(), arg.size());
        *(char *)((uintptr_t)native_addr + arg.size()) = 0;
        _append(&addr, sizeof(uint32_t));
    }

    void add(const char *arg) { add(std::string(arg)); }

    char *get() const
    {
        auto inst = wasm_runtime_get_module_inst(exec_env_);
        uint32_t addr = wasm_runtime_module_dup_data(
            inst, (const char *)buffer_, current_loc_);
        EXPECT_NE(addr, 0);
        return (char *)wasm_runtime_addr_app_to_native(inst, addr);
    }
};

/* Get memory space in app */
class AppMemory
{
  private:
    wasm_exec_env_t exec_env_;
    void *native_addr_;
    uint32_t app_addr_;

  public:
    AppMemory(wasm_exec_env_t exec_env, uint32_t size)
      : exec_env_(exec_env)
    {
        app_addr_ = wasm_runtime_module_malloc(get_module_inst(exec_env_), size,
                                               &native_addr_);
    }

    ~AppMemory()
    {
        wasm_runtime_module_free(get_module_inst(exec_env_), app_addr_);
    }

    void *get_native_addr() const
    {
        return wasm_runtime_addr_app_to_native(get_module_inst(exec_env_),
                                               app_addr_);
    }
    uint32_t get_app_addr() const { return app_addr_; }
};

/* Put the data to app */
class AppData
{
  private:
    wasm_exec_env_t exec_env_;
    void *native_addr_;
    uint32_t app_addr_;

  public:
    AppData(wasm_exec_env_t exec_env, void *data, uint32_t size)
      : exec_env_(exec_env)
    {
        app_addr_ = wasm_runtime_module_dup_data(get_module_inst(exec_env_),
                                                 (const char *)data, size);
    }

    AppData(wasm_exec_env_t exec_env, std::string str)
      : exec_env_(exec_env)
    {
        app_addr_ = wasm_runtime_module_dup_data(get_module_inst(exec_env_),
                                                 (const char *)str.c_str(),
                                                 str.size() + 1);
    }

    ~AppData()
    {
        wasm_runtime_module_free(get_module_inst(exec_env_), app_addr_);
    }

    void *get_native_addr() const
    {
        return wasm_runtime_addr_app_to_native(get_module_inst(exec_env_),
                                               app_addr_);
    }
    uint32_t get_app_addr() const { return app_addr_; }
};
// Copyright (C) 2016-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_PLUGIN_HPP
#define VSOMEIP_PLUGIN_HPP

#include <memory>

#if WIN32
    #if VSOMEIP_DLL_COMPILATION_PLUGIN
        #define VSOMEIP_IMPORT_EXPORT_PLUGIN __declspec(dllexport)
    #else
        #define VSOMEIP_IMPORT_EXPORT_PLUGIN __declspec(dllimport)
    #endif
#else
    #define VSOMEIP_IMPORT_EXPORT_PLUGIN
#endif

#define VSOMEIP_PLUGIN_INIT_SYMBOL "vsomeip_plugin_init"

namespace vsomeip {

enum class plugin_type_e : uint8_t {
    APPLICATION_PLUGIN,
    PRE_CONFIGURATION_PLUGIN,
    CONFIGURATION_PLUGIN,
    SD_RUNTIME_PLUGIN
};

class plugin;
typedef std::shared_ptr<plugin> (*create_plugin_func)();
typedef create_plugin_func (*plugin_init_func)();

/**
 * Base class for all plug-ins
 */
class VSOMEIP_IMPORT_EXPORT_PLUGIN plugin {
public:
    virtual ~plugin() {}

    virtual uint32_t get_plugin_version() const = 0;
    virtual const std::string &get_plugin_name() const = 0;
    virtual plugin_type_e get_plugin_type() const = 0;
};

template<class Plugin_>
class plugin_impl : public plugin {
public:
    static std::shared_ptr<plugin> get_plugin() {
        return std::make_shared<Plugin_>();
    }

    plugin_impl(const std::string &_name, uint32_t _version,
                plugin_type_e _type) {
        name_ = _name;
        version_ = _version;
        type_ = _type;
    }

    const std::string &get_plugin_name() const {
        return name_;
    }

    uint32_t get_plugin_version() const {
        return version_;
    }

    plugin_type_e get_plugin_type() const {
        return type_;
    }

private:
    uint32_t version_;
    std::string name_;
    plugin_type_e type_;
};

#define VSOMEIP_PLUGIN(class_name) \
    extern "C" { \
        VSOMEIP_EXPORT vsomeip::create_plugin_func vsomeip_plugin_init() { \
            return class_name::get_plugin; \
        } \
    }

} // namespace vsomeip

#endif // VSOMEIP_PLUGIN_HPP

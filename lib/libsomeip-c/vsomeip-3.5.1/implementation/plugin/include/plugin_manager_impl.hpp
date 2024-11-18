// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PLUGIN_MANAGER_IMPL_HPP
#define VSOMEIP_V3_PLUGIN_MANAGER_IMPL_HPP

#include <vsomeip/internal/plugin_manager.hpp>

#include <map>
#include <chrono>
#include <mutex>
#include <set>

#include <vsomeip/constants.hpp>
#include <vsomeip/export.hpp>
#include <vsomeip/plugin.hpp>

namespace vsomeip_v3 {

class plugin_manager_impl : public plugin_manager {
public:
        VSOMEIP_EXPORT static std::shared_ptr<plugin_manager_impl> get();

        plugin_manager_impl();

        ~plugin_manager_impl();

        VSOMEIP_EXPORT void load_plugins();

        VSOMEIP_EXPORT std::shared_ptr<plugin> get_plugin(plugin_type_e _type,
                const std::string &_name);

        VSOMEIP_EXPORT std::shared_ptr<plugin> load_plugin(
                const std::string& _library, plugin_type_e _type,
                const uint32_t _version);

        VSOMEIP_EXPORT bool unload_plugin(plugin_type_e _type);

        VSOMEIP_EXPORT void * load_library(const std::string &_path);
        VSOMEIP_EXPORT void * load_symbol(void * _handle, const std::string &_symbol);
        VSOMEIP_EXPORT void unload_library(void * _handle);

private:
        void add_plugin(const std::shared_ptr<plugin> &_plugin, const std::string& _name);

        bool plugins_loaded_;
        std::mutex loader_mutex_;

        std::map<plugin_type_e, std::map<std::string, std::shared_ptr<plugin> > > plugins_;
        std::map<plugin_type_e, std::map<std::string, void*> > handles_;
        std::recursive_mutex plugins_mutex_;

        static std::shared_ptr<plugin_manager_impl> the_plugin_manager__;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PLUGIN_MANAGER_IMPL_HPP

// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#ifdef _WIN32
    #include <iostream>
    #include <tchar.h>
    #include <intrin.h>
#else
    #include <dlfcn.h>
    #include <errno.h>
    #include <signal.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <thread>
    #include <sstream>
#endif

#include <sys/stat.h>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/bithelper.hpp"
#include "../include/utility.hpp"
#include "../../configuration/include/configuration.hpp"

namespace vsomeip_v3 {

std::mutex utility::mutex__;
std::map<std::string, utility::data_t> utility::data__;

utility::data_t::data_t()
    : next_client_(VSOMEIP_CLIENT_UNSET),
#ifdef _WIN32
        lock_handle_(INVALID_HANDLE_VALUE)
#else
        lock_fd_(-1)
#endif
{}

uint64_t utility::get_message_size(const byte_t *_data, size_t _size) {
    uint64_t its_size(0);
    if (VSOMEIP_SOMEIP_HEADER_SIZE <= _size) {
        its_size = VSOMEIP_SOMEIP_HEADER_SIZE
                + bithelper::read_uint32_be(&_data[4]);
    }
    return its_size;
}

uint32_t utility::get_payload_size(const byte_t *_data, uint32_t _size) {
    if(_size <= VSOMEIP_FULL_HEADER_SIZE)
        return 0;

    uint32_t length_ = bithelper::read_uint32_be(&_data[4]);

    if(length_ <= VSOMEIP_SOMEIP_HEADER_SIZE)
        return 0;

    if (_size != (VSOMEIP_SOMEIP_HEADER_SIZE + length_))
        return 0;

    return length_ - VSOMEIP_SOMEIP_HEADER_SIZE;
}

bool utility::is_routing_manager(const std::string &_network) {
    // Only the first caller can become routing manager.
    // Therefore, subsequent calls can be immediately answered...
    std::lock_guard<std::mutex> its_lock(mutex__);
    if (data__.find(_network) != data__.end())
        return false;

    auto r = data__.insert(std::make_pair(_network, data_t()));
    if (!r.second)
        return false;

#ifdef _WIN32
    wchar_t its_tmp_folder[MAX_PATH];
    if (GetTempPathW(MAX_PATH, its_tmp_folder)) {
        std::wstring its_lockfile(its_tmp_folder);
        std::string its_network(_network + ".lck");
        its_lockfile.append(its_network.begin(), its_network.end());
        r.first->second.lock_handle_ = CreateFileW(its_lockfile.c_str(), GENERIC_READ, 0, NULL, CREATE_NEW, 0, NULL);
        if (r.first->second.lock_handle_ == INVALID_HANDLE_VALUE) {
            VSOMEIP_ERROR << __func__ << ": CreateFileW failed: " << std::hex << GetLastError();
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": Could not get temp folder: "
                << std::hex << GetLastError();
        r.first->second.lock_handle_ = INVALID_HANDLE_VALUE;
    }

    return (r.first->second.lock_handle_ != INVALID_HANDLE_VALUE);
#else
    std::string its_base_path(VSOMEIP_BASE_PATH + _network);
    std::string its_lockfile(its_base_path + ".lck");
    int its_lock_ctrl(-1);

    struct flock its_lock_data = { F_WRLCK, SEEK_SET, 0, 0, 0 };

    r.first->second.lock_fd_ = open(its_lockfile.c_str(), O_WRONLY | O_CREAT, S_IWUSR | S_IWGRP);
    if (-1 != r.first->second.lock_fd_) {
        its_lock_data.l_pid = getpid();
        its_lock_ctrl = fcntl(r.first->second.lock_fd_, F_SETLK, &its_lock_data);
    } else {
        VSOMEIP_ERROR << __func__
                << ": Could not open " << its_lockfile << ": " << std::strerror(errno);
    }

    return (its_lock_ctrl != -1);
#endif
}

void utility::remove_lockfile(const std::string &_network) {
    std::lock_guard<std::mutex> its_lock(mutex__);

    auto r = data__.find(_network);
    if (r == data__.end()) // No need to do anything as automatic
        return;

#ifdef _WIN32
    if (r->second.lock_handle_ != INVALID_HANDLE_VALUE) {
        if (CloseHandle(r->second.lock_handle_) == 0) {
            VSOMEIP_ERROR << __func__ << ": CloseHandle failed."
                    << std::hex << GetLastError();
        }
        wchar_t its_tmp_folder[MAX_PATH];
        if (GetTempPathW(MAX_PATH, its_tmp_folder)) {
            std::wstring its_lockfile(its_tmp_folder);
            std::string its_network(_network + ".lck");
            its_lockfile.append(its_network.begin(), its_network.end());
            if (DeleteFileW(its_lockfile.c_str()) == 0) {
                VSOMEIP_ERROR << __func__ << ": DeleteFileW failed: "
                        << std::hex << GetLastError();

            }
        } else {
            VSOMEIP_ERROR << __func__ << ": Could not get temp folder."
                    << std::hex << GetLastError();
        }
    }
#else
    std::string its_base_path(VSOMEIP_BASE_PATH + _network);
    std::string its_lockfile(its_base_path + ".lck");

    if (r->second.lock_fd_ != -1) {
       if (close(r->second.lock_fd_) == -1) {
           VSOMEIP_ERROR << __func__ << ": Could not close lock_fd__"
                   << std::strerror(errno);
       }
    }
    if (remove(its_lockfile.c_str()) == -1) {
        VSOMEIP_ERROR << __func__ << ": Could not remove " << its_lockfile
                << ": " << std::strerror(errno);
    }
#endif
    data__.erase(_network);
}

bool utility::exists(const std::string &_path) {
    struct stat its_stat;
    return (stat(_path.c_str(), &its_stat) == 0);
}

bool utility::is_file(const std::string &_path) {
    struct stat its_stat;
    if (stat(_path.c_str(), &its_stat) == 0) {
        if (its_stat.st_mode & S_IFREG)
            return true;
    }
    return false;
}

bool utility::is_folder(const std::string &_path) {
    struct stat its_stat;
    if (stat(_path.c_str(), &its_stat) == 0) {
        if (its_stat.st_mode & S_IFDIR)
            return true;
    }
    return false;
}

std::string utility::get_base_path(const std::string &_network) {
    return std::string(VSOMEIP_BASE_PATH + _network + "-");
}

client_t
utility::request_client_id(
        const std::shared_ptr<configuration> &_config,
        const std::string &_name, client_t _client) {
    std::lock_guard<std::mutex> its_lock(mutex__);
    static const std::uint16_t its_max_num_clients = get_max_client_number(_config);

    static const std::uint16_t its_diagnosis_mask = _config->get_diagnosis_mask();
    static const std::uint16_t its_client_mask = static_cast<std::uint16_t>(~its_diagnosis_mask);
    static const client_t its_masked_diagnosis_address = static_cast<client_t>(
            (_config->get_diagnosis_address() << 8) & its_diagnosis_mask);
    static const client_t its_biggest_client = its_masked_diagnosis_address | its_client_mask;
    static const client_t its_smallest_client = its_masked_diagnosis_address;

    auto r = data__.find(_config->get_network());
    if (r == data__.end())
        return VSOMEIP_CLIENT_UNSET;

    if (r->second.next_client_ == VSOMEIP_CLIENT_UNSET) {
        r->second.next_client_ = its_smallest_client;
    }

    if (_client != VSOMEIP_CLIENT_UNSET) { // predefined client identifier
        const auto its_iterator = r->second.used_clients_.find(_client);
        if (its_iterator == r->second.used_clients_.end()) { // unused identifier
            r->second.used_clients_[_client] = _name;
            return _client;
        } else { // already in use

            // The name matches the assigned name --> return client
            // NOTE: THIS REQUIRES A CONSISTENT CONFIGURATION!!!
            if (its_iterator->second == _name) {
                return _client;
            }

            VSOMEIP_WARNING << "Requested client identifier "
                    << std::setw(4) << std::setfill('0')
                    << std::hex << _client
                    << " is already used by application \""
                    << its_iterator->second
                    << "\".";
            // intentionally fall through
        }
    }

    if (r->second.next_client_ == its_biggest_client) {
        // start at beginning of client range again when the biggest client was reached
        r->second.next_client_ = its_smallest_client;
    }
    std::uint16_t increase_count = 0;
    do {
        r->second.next_client_ = (r->second.next_client_
                & static_cast<std::uint16_t>(~its_client_mask)) // save diagnosis address bits
                | (static_cast<std::uint16_t>((r->second.next_client_ // set all diagnosis address bits to one
                        | static_cast<std::uint16_t>(~its_client_mask)) + 1u) //  and add one to the result
                                & its_client_mask); // set the diagnosis address bits to zero again
        if (increase_count++ == its_max_num_clients) {
            VSOMEIP_ERROR << __func__ << " no free client IDs left! "
                    "Max amount of possible concurrent active vsomeip "
                    "applications reached ("  << std::dec << r->second.used_clients_.size()
                    << ").";
            return VSOMEIP_CLIENT_UNSET;
        }
    } while (r->second.used_clients_.find(r->second.next_client_) != r->second.used_clients_.end()
            || _config->is_configured_client_id(r->second.next_client_));

    r->second.used_clients_[r->second.next_client_] = _name;
    return r->second.next_client_;
}

void
utility::release_client_id(const std::string &_network, client_t _client) {
    std::lock_guard<std::mutex> its_lock(mutex__);
    auto r = data__.find(_network);
    if (r != data__.end())
        r->second.used_clients_.erase(_client);
}

std::set<client_t>
utility::get_used_client_ids(const std::string &_network) {
    std::lock_guard<std::mutex> its_lock(mutex__);
    std::set<client_t> its_used_clients;
    auto r = data__.find(_network);
    if (r != data__.end()) {
        for (const auto& c : r->second.used_clients_)
            its_used_clients.insert(c.first);
    }
    return its_used_clients;
}

void utility::reset_client_ids(const std::string &_network) {
    std::lock_guard<std::mutex> its_lock(mutex__);
    auto r = data__.find(_network);
    if (r != data__.end()) {
        r->second.used_clients_.clear();
        r->second.next_client_ = VSOMEIP_CLIENT_UNSET;
    }
}

void utility::set_thread_niceness(int _nice) noexcept {
#if defined(__linux__)
    errno = 0;
    if ((nice(_nice) == -1) && (errno < 0)) {
        VSOMEIP_WARNING << "failed to set niceness for thread " << std::this_thread::get_id() << " (error: " << strerror(errno) << ')';
        return;
    }
#else
    (void)_nice;
#endif
}

std::uint16_t utility::get_max_client_number(
        const std::shared_ptr<configuration> &_config) {
    std::uint16_t its_max_clients(0);
    const int bits_for_clients =
#ifdef _WIN32
            __popcnt(
#else
            __builtin_popcount(
#endif
            static_cast<std::uint16_t>(~_config->get_diagnosis_mask()));
    for (int var = 0; var < bits_for_clients; ++var) {
        its_max_clients = static_cast<std::uint16_t>(its_max_clients | (1 << var));
    }
    return its_max_clients;
}

} // namespace vsomeip_v3

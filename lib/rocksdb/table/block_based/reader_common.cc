//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
#include "table/block_based/reader_common.h"

#include "monitoring/perf_context_imp.h"
#include "rocksdb/table.h"
#include "table/format.h"
#include "util/coding.h"
#include "util/crc32c.h"
#include "util/string_util.h"

namespace ROCKSDB_NAMESPACE {
void ForceReleaseCachedEntry(void* arg, void* h) {
  Cache* cache = static_cast<Cache*>(arg);
  Cache::Handle* handle = static_cast<Cache::Handle*>(h);
  cache->Release(handle, true /* erase_if_last_ref */);
}

// WART: this is specific to block-based table
Status VerifyBlockChecksum(const Footer& footer, const char* data,
                           size_t block_size, const std::string& file_name,
                           uint64_t offset) {
  PERF_TIMER_GUARD(block_checksum_time);

  assert(footer.GetBlockTrailerSize() == 5);
  ChecksumType type = footer.checksum_type();

  // After block_size bytes is compression type (1 byte), which is part of
  // the checksummed section.
  size_t len = block_size + 1;
  // And then the stored checksum value (4 bytes).
  uint32_t stored = DecodeFixed32(data + len);

  uint32_t computed = ComputeBuiltinChecksum(type, data, len);

  // Unapply context to 'stored' rather than apply to 'computed, for people
  // who might look for reference crc value in error message
  uint32_t modifier =
      ChecksumModifierForContext(footer.base_context_checksum(), offset);
  stored -= modifier;

  if (stored == computed) {
    return Status::OK();
  } else {
    // Unmask for people who might look for reference crc value
    if (type == kCRC32c) {
      stored = crc32c::Unmask(stored);
      computed = crc32c::Unmask(computed);
    }
    return Status::Corruption(
        "block checksum mismatch: stored" +
        std::string(modifier ? "(context removed)" : "") + " = " +
        std::to_string(stored) + ", computed = " + std::to_string(computed) +
        ", type = " + std::to_string(type) + "  in " + file_name + " offset " +
        std::to_string(offset) + " size " + std::to_string(block_size));
  }
}
}  // namespace ROCKSDB_NAMESPACE

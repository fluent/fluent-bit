//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "db_stress_tool/db_stress_shared_state.h"
#ifdef GFLAGS
#pragma once
#include "db_stress_tool/db_stress_test_base.h"
namespace ROCKSDB_NAMESPACE {
void ThreadBody(void* /*thread_state*/);
bool RunStressTest(SharedState*);
}  // namespace ROCKSDB_NAMESPACE
#endif  // GFLAGS

//  Copyright (c) Meta Platforms, Inc. and affiliates.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include "db/db_test_util.h"
#include "port/port.h"
#include "util/random.h"

namespace ROCKSDB_NAMESPACE {

class DBClipTest : public DBTestBase {
 public:
  DBClipTest() : DBTestBase("db_clip_test", /*env_do_fsync=*/true) {}
};

TEST_F(DBClipTest, TestClipRange) {
  Options options = CurrentOptions();
  options.write_buffer_size = 10 * 1024 * 1024;
  options.max_bytes_for_level_multiplier = 2;
  options.num_levels = 3;
  options.max_background_compactions = 3;
  options.disable_auto_compactions = true;
  options.statistics = CreateDBStatistics();

  DestroyAndReopen(options);
  int32_t value_size = 10 * 1024;  // 10 KB

  Random rnd(301);
  std::map<int32_t, std::string> values;

  // file [0 => 100), [100 => 200), ... [900, 1000)
  for (auto i = 0; i < 10; i++) {
    for (auto j = 0; j < 100; j++) {
      auto k = i * 100 + j;
      values[k] = rnd.RandomString(value_size);
      ASSERT_OK(Put(Key(k), values[k]));
    }
    ASSERT_OK(Flush());
  }
  ASSERT_EQ("10", FilesPerLevel(0));
  auto begin_key = Key(251), end_key = Key(751);
  ASSERT_OK(
      db_->ClipColumnFamily(db_->DefaultColumnFamily(), begin_key, end_key));

  for (auto i = 0; i < 251; i++) {
    ReadOptions ropts;
    std::string result;
    auto s = db_->Get(ropts, Key(i), &result);
    ASSERT_TRUE(s.IsNotFound());
  }
  for (auto i = 251; i < 751; i++) {
    ASSERT_EQ(Get(Key(i)), values[i]);
  }
  for (auto i = 751; i < 1000; i++) {
    ReadOptions ropts;
    std::string result;
    auto s = db_->Get(ropts, Key(i), &result);
    ASSERT_TRUE(s.IsNotFound());
  }

  std::vector<LiveFileMetaData> all_metadata;
  db_->GetLiveFilesMetaData(&all_metadata);
  for (auto& md : all_metadata) {
    // make sure clip_begin_key <= file_smallestkey <= file_largestkey <=
    // clip_end_key
    bool in_range = false;

    if (options.comparator->Compare(begin_key, md.smallestkey) <= 0 &&
        options.comparator->Compare(end_key, md.largestkey) > 0) {
      in_range = true;
    }
    ASSERT_TRUE(in_range);
  }

  CompactRangeOptions compact_options;
  compact_options.change_level = true;
  compact_options.target_level = 2;
  ASSERT_OK(db_->CompactRange(compact_options, nullptr, nullptr));
  ASSERT_EQ("0,0,3", FilesPerLevel(0));

  for (auto i = 0; i < 10; i += 2) {
    for (auto j = 0; j < 100; j++) {
      auto k = i * 100 + j;
      ASSERT_OK(Put(Key(k), values[k]));
    }
    ASSERT_OK(Flush());
  }
  ASSERT_EQ("5,0,3", FilesPerLevel(0));
  ASSERT_OK(dbfull()->TEST_CompactRange(0, nullptr, nullptr));
  ASSERT_EQ("0,5,3", FilesPerLevel(0));

  for (auto i = 1; i < 10; i += 2) {
    for (auto j = 0; j < 100; j++) {
      auto k = i * 100 + j;
      ASSERT_OK(Put(Key(k), values[k]));
    }
    ASSERT_OK(Flush());
  }
  ASSERT_EQ("5,5,3", FilesPerLevel(0));

  auto begin_key_2 = Key(222), end_key_2 = Key(888);

  ASSERT_OK(db_->ClipColumnFamily(db_->DefaultColumnFamily(), begin_key_2,
                                  end_key_2));

  for (auto i = 0; i < 222; i++) {
    ReadOptions ropts;
    std::string result;
    auto s = db_->Get(ropts, Key(i), &result);
    ASSERT_TRUE(s.IsNotFound());
  }
  for (auto i = 222; i < 888; i++) {
    ASSERT_EQ(Get(Key(i)), values[i]);
  }
  for (auto i = 888; i < 1000; i++) {
    ReadOptions ropts;
    std::string result;
    auto s = db_->Get(ropts, Key(i), &result);
    ASSERT_TRUE(s.IsNotFound());
  }

  std::vector<LiveFileMetaData> all_metadata_2;
  db_->GetLiveFilesMetaData(&all_metadata_2);
  for (auto& md : all_metadata_2) {
    // make sure clip_begin_key <= file_smallestkey <= file_largestkey <=
    // clip_end_key
    bool in_range = false;
    if (begin_key_2.compare(md.smallestkey) <= 0 &&
        end_key_2.compare(md.largestkey) > 0) {
      in_range = true;
    }
    ASSERT_TRUE(in_range);
  }
}
}  // namespace ROCKSDB_NAMESPACE

int main(int argc, char** argv) {
  ROCKSDB_NAMESPACE::port::InstallStackTraceHandler();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
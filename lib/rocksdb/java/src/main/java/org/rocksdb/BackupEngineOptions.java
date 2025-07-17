// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

package org.rocksdb;

import java.io.File;

/**
 * <p>BackupEngineOptions controls the behavior of a
 * {@link org.rocksdb.BackupEngine}.
 * </p>
 * <p>Note that dispose() must be called before an Options instance
 * become out-of-scope to release the allocated memory in c++.</p>
 *
 * @see org.rocksdb.BackupEngine
 */
public class BackupEngineOptions extends RocksObject {
  private Env backupEnv = null;
  private Logger infoLog = null;
  private RateLimiter backupRateLimiter = null;
  private RateLimiter restoreRateLimiter = null;

  /**
   * <p>BackupEngineOptions constructor.</p>
   *
   * @param path Where to keep the backup files. Has to be different from db
   *   name. Best to set this to {@code db name_ + "/backups"}
   * @throws java.lang.IllegalArgumentException if illegal path is used.
   */
  public BackupEngineOptions(final String path) {
    super(newBackupEngineOptions(ensureWritableFile(path)));
  }

  private static String ensureWritableFile(final String path) {
    final File backupPath = path == null ? null : new File(path);
    if (backupPath == null || !backupPath.isDirectory() ||
        !backupPath.canWrite()) {
      throw new IllegalArgumentException("Illegal path provided.");
    } else {
      return path;
    }
  }

  /**
   * <p>Returns the path to the BackupEngine directory.</p>
   *
   * @return the path to the BackupEngine directory.
   */
  public String backupDir() {
    assert(isOwningHandle());
    return backupDir(nativeHandle_);
  }

  /**
   * Backup Env object. It will be used for backup file I/O. If it's
   * null, backups will be written out using DBs Env. Otherwise,
   * backup's I/O will be performed using this object.
   * <p>
   * Default: null
   *
   * @param env The environment to use
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setBackupEnv(final Env env) {
    assert(isOwningHandle());
    setBackupEnv(nativeHandle_, env.nativeHandle_);
    this.backupEnv = env;
    return this;
  }

  /**
   * Backup Env object. It will be used for backup file I/O. If it's
   * null, backups will be written out using DBs Env. Otherwise,
   * backup's I/O will be performed using this object.
   * <p>
   * Default: null
   *
   * @return The environment in use
   */
  public Env backupEnv() {
    return this.backupEnv;
  }

  /**
   * <p>Share table files between backups.</p>
   *
   * @param shareTableFiles If {@code share_table_files == true}, backup will
   *   assume that table files with same name have the same contents. This
   *   enables incremental backups and avoids unnecessary data copies. If
   *   {@code share_table_files == false}, each backup will be on its own and
   *   will not share any data with other backups.
   *
   * <p>Default: true</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setShareTableFiles(final boolean shareTableFiles) {
    assert(isOwningHandle());
    setShareTableFiles(nativeHandle_, shareTableFiles);
    return this;
  }

  /**
   * <p>Share table files between backups.</p>
   *
   * @return boolean value indicating if SST files will be shared between
   *     backups.
   */
  public boolean shareTableFiles() {
    assert(isOwningHandle());
    return shareTableFiles(nativeHandle_);
  }

  /**
   * Set the logger to use for Backup info and error messages
   *
   * @param logger The logger to use for the backup
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setInfoLog(final Logger logger) {
    assert(isOwningHandle());
    setInfoLog(nativeHandle_, logger.nativeHandle_);
    this.infoLog = logger;
    return this;
  }

  /**
   * Set the logger to use for Backup info and error messages
   * <p>
   * Default: null
   *
   * @return The logger in use for the backup
   */
  public Logger infoLog() {
    return this.infoLog;
  }

  /**
   * <p>Set synchronous backups.</p>
   *
   * @param sync If {@code sync == true}, we can guarantee you'll get consistent
   *   backup even on a machine crash/reboot. Backup process is slower with sync
   *   enabled. If {@code sync == false}, we don't guarantee anything on machine
   *   reboot. However, chances are some backups are consistent.
   *
   * <p>Default: true</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setSync(final boolean sync) {
    assert(isOwningHandle());
    setSync(nativeHandle_, sync);
    return this;
  }

  /**
   * <p>Are synchronous backups activated.</p>
   *
   * @return boolean value if synchronous backups are configured.
   */
  public boolean sync() {
    assert(isOwningHandle());
    return sync(nativeHandle_);
  }

  /**
   * <p>Set if old data will be destroyed.</p>
   *
   * @param destroyOldData If true, it will delete whatever backups there are
   *   already.
   *
   * <p>Default: false</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setDestroyOldData(final boolean destroyOldData) {
    assert(isOwningHandle());
    setDestroyOldData(nativeHandle_, destroyOldData);
    return this;
  }

  /**
   * <p>Returns if old data will be destroyed will performing new backups.</p>
   *
   * @return boolean value indicating if old data will be destroyed.
   */
  public boolean destroyOldData() {
    assert(isOwningHandle());
    return destroyOldData(nativeHandle_);
  }

  /**
   * <p>Set if log files shall be persisted.</p>
   *
   * @param backupLogFiles If false, we won't back up log files. This option can
   *   be useful for backing up in-memory databases where log file are
   *   persisted, but table files are in memory.
   *
   * <p>Default: true</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setBackupLogFiles(final boolean backupLogFiles) {
    assert(isOwningHandle());
    setBackupLogFiles(nativeHandle_, backupLogFiles);
    return this;
  }

  /**
   * <p>Return information if log files shall be persisted.</p>
   *
   * @return boolean value indicating if log files will be persisted.
   */
  public boolean backupLogFiles() {
    assert(isOwningHandle());
    return backupLogFiles(nativeHandle_);
  }

  /**
   * <p>Set backup rate limit.</p>
   *
   * @param backupRateLimit Max bytes that can be transferred in a second during
   *   backup. If 0 or negative, then go as fast as you can.
   *
   * <p>Default: 0</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setBackupRateLimit(final long backupRateLimit) {
    assert(isOwningHandle());
    setBackupRateLimit(nativeHandle_, (backupRateLimit <= 0) ? 0 : backupRateLimit);
    return this;
  }

  /**
   * <p>Return backup rate limit which described the max bytes that can be
   * transferred in a second during backup.</p>
   *
   * @return numerical value describing the backup transfer limit in bytes per
   *   second.
   */
  public long backupRateLimit() {
    assert(isOwningHandle());
    return backupRateLimit(nativeHandle_);
  }

  /**
   * Backup rate limiter. Used to control transfer speed for backup. If this is
   * not null, {@link #backupRateLimit()} is ignored.
   * <p>
   * Default: null
   *
   * @param backupRateLimiter The rate limiter to use for the backup
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setBackupRateLimiter(final RateLimiter backupRateLimiter) {
    assert(isOwningHandle());
    setBackupRateLimiter(nativeHandle_, backupRateLimiter.nativeHandle_);
    this.backupRateLimiter = backupRateLimiter;
    return this;
  }

  /**
   * Backup rate limiter. Used to control transfer speed for backup. If this is
   * not null, {@link #backupRateLimit()} is ignored.
   * <p>
   * Default: null
   *
   * @return The rate limiter in use for the backup
   */
  public RateLimiter backupRateLimiter() {
    assert(isOwningHandle());
    return this.backupRateLimiter;
  }

  /**
   * <p>Set restore rate limit.</p>
   *
   * @param restoreRateLimit Max bytes that can be transferred in a second
   *   during restore. If 0 or negative, then go as fast as you can.
   *
   * <p>Default: 0</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setRestoreRateLimit(final long restoreRateLimit) {
    assert(isOwningHandle());
    setRestoreRateLimit(nativeHandle_, (restoreRateLimit <= 0) ? 0 : restoreRateLimit);
    return this;
  }

  /**
   * <p>Return restore rate limit which described the max bytes that can be
   * transferred in a second during restore.</p>
   *
   * @return numerical value describing the restore transfer limit in bytes per
   *   second.
   */
  public long restoreRateLimit() {
    assert(isOwningHandle());
    return restoreRateLimit(nativeHandle_);
  }

  /**
   * Restore rate limiter. Used to control transfer speed during restore. If
   * this is not null, {@link #restoreRateLimit()} is ignored.
   * <p>
   * Default: null
   *
   * @param restoreRateLimiter The rate limiter to use during restore
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setRestoreRateLimiter(final RateLimiter restoreRateLimiter) {
    assert(isOwningHandle());
    setRestoreRateLimiter(nativeHandle_, restoreRateLimiter.nativeHandle_);
    this.restoreRateLimiter = restoreRateLimiter;
    return this;
  }

  /**
   * Restore rate limiter. Used to control transfer speed during restore. If
   * this is not null, {@link #restoreRateLimit()} is ignored.
   * <p>
   * Default: null
   *
   * @return The rate limiter in use during restore
   */
  public RateLimiter restoreRateLimiter() {
    assert(isOwningHandle());
    return this.restoreRateLimiter;
  }

  /**
   * <p>Only used if share_table_files is set to true. If true, will consider
   * that backups can come from different databases, hence a sst is not uniquely
   * identified by its name, but by the triple (file name, crc32, file length)
   * </p>
   *
   * @param shareFilesWithChecksum boolean value indicating if SST files are
   *   stored using the triple (file name, crc32, file length) and not its name.
   *
   * <p>Note: this is an experimental option, and you'll need to set it manually
   * turn it on only if you know what you're doing*</p>
   *
   * <p>Default: false</p>
   *
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setShareFilesWithChecksum(final boolean shareFilesWithChecksum) {
    assert(isOwningHandle());
    setShareFilesWithChecksum(nativeHandle_, shareFilesWithChecksum);
    return this;
  }

  /**
   * <p>Return of share files with checksum is active.</p>
   *
   * @return boolean value indicating if share files with checksum
   *     is active.
   */
  public boolean shareFilesWithChecksum() {
    assert(isOwningHandle());
    return shareFilesWithChecksum(nativeHandle_);
  }

  /**
   * Up to this many background threads will copy files for
   * {@link BackupEngine#createNewBackup(RocksDB, boolean)} and
   * {@link BackupEngine#restoreDbFromBackup(int, String, String, RestoreOptions)}
   *
   * Default: 1
   *
   * @param maxBackgroundOperations The maximum number of background threads
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setMaxBackgroundOperations(final int maxBackgroundOperations) {
    assert(isOwningHandle());
    setMaxBackgroundOperations(nativeHandle_, maxBackgroundOperations);
    return this;
  }

  /**
   * Up to this many background threads will copy files for
   * {@link BackupEngine#createNewBackup(RocksDB, boolean)} and
   * {@link BackupEngine#restoreDbFromBackup(int, String, String, RestoreOptions)}
   *
   * Default: 1
   *
   * @return The maximum number of background threads
   */
  public int maxBackgroundOperations() {
    assert(isOwningHandle());
    return maxBackgroundOperations(nativeHandle_);
  }

  /**
   * During backup user can get callback every time next
   * {@link #callbackTriggerIntervalSize()} bytes being copied.
   * <p>
   * Default: 4194304
   *
   * @param callbackTriggerIntervalSize The interval size for the
   *     callback trigger
   * @return instance of current BackupEngineOptions.
   */
  public BackupEngineOptions setCallbackTriggerIntervalSize(
      final long callbackTriggerIntervalSize) {
    assert(isOwningHandle());
    setCallbackTriggerIntervalSize(nativeHandle_, callbackTriggerIntervalSize);
    return this;
  }

  /**
   * During backup user can get callback every time next
   * {@code #callbackTriggerIntervalSize()} bytes being copied.
   * <p>
   * Default: 4194304
   *
   * @return The interval size for the callback trigger
   */
  public long callbackTriggerIntervalSize() {
    assert(isOwningHandle());
    return callbackTriggerIntervalSize(nativeHandle_);
  }

  private static native long newBackupEngineOptions(final String path);
  private static native String backupDir(long handle);
  private static native void setBackupEnv(final long handle, final long envHandle);
  private static native void setShareTableFiles(long handle, boolean flag);
  private static native boolean shareTableFiles(long handle);
  private static native void setInfoLog(final long handle, final long infoLogHandle);
  private static native void setSync(long handle, boolean flag);
  private static native boolean sync(long handle);
  private static native void setDestroyOldData(long handle, boolean flag);
  private static native boolean destroyOldData(long handle);
  private static native void setBackupLogFiles(long handle, boolean flag);
  private static native boolean backupLogFiles(long handle);
  private static native void setBackupRateLimit(long handle, long rateLimit);
  private static native long backupRateLimit(long handle);
  private static native void setBackupRateLimiter(long handle, long rateLimiterHandle);
  private static native void setRestoreRateLimit(long handle, long rateLimit);
  private static native long restoreRateLimit(long handle);
  private static native void setRestoreRateLimiter(final long handle, final long rateLimiterHandle);
  private static native void setShareFilesWithChecksum(long handle, boolean flag);
  private static native boolean shareFilesWithChecksum(long handle);
  private static native void setMaxBackgroundOperations(
      final long handle, final int maxBackgroundOperations);
  private static native int maxBackgroundOperations(final long handle);
  private static native void setCallbackTriggerIntervalSize(
      final long handle, long callbackTriggerIntervalSize);
  private static native long callbackTriggerIntervalSize(final long handle);
  @Override
  protected final void disposeInternal(final long handle) {
    disposeInternalJni(handle);
  }

  private static native void disposeInternalJni(final long handle);
}

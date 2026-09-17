/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Restore browser-local files before main starts. ChunkIO's sync/close writes
 * mappings into this virtual filesystem; sync() below commits those files to
 * IndexedDB. Call it only while writers are quiescent. It is not crash-atomic
 * with an output acknowledgement, nor a replacement for cio_chunk_sync().
 */
Module['preRun'] = typeof Module['preRun'] === 'function' ?
                   [Module['preRun']] : (Module['preRun'] || []);
Module['preRun'].push(function() {
    var path = Module['flbStoragePath'] || '/storage';
    var persistent = !ENVIRONMENT_IS_NODE &&
                     Module['flbStoragePersistent'] !== false;
    var restored = false;
    var pending = Promise.resolve();

    if (!/^\/[A-Za-z0-9_-]+$/.test(path)) {
        abort('flbStoragePath must be a dedicated top-level directory, e.g. /storage');
    }

    FS.mkdirTree(path);
    Module['flbStorage'] = {
        'path': path,
        'persistent': persistent,
        'sync': function() {
            if (!restored) {
                return Promise.reject(new Error('Browser storage has not been restored'));
            }
            var sync = function() {
                return new Promise(function(resolve, reject) {
                    if (!persistent) {
                        resolve();
                        return;
                    }
                    FS.syncfs(false, function(error) {
                        if (error) { reject(error); }
                        else { resolve(); }
                    });
                });
            };
            /* Serialize commits, but allow a failed commit to be retried. */
            pending = pending.then(sync, sync);
            return pending;
        }
    };

    if (!persistent) {
        restored = true;
        return;
    }

    addRunDependency('flb-storage-restore');
    try {
        FS.mount(IDBFS, {}, path);
        FS.syncfs(true, function(error) {
            if (error) {
                abort('Unable to restore browser storage: ' + error);
                return;
            }
            restored = true;
            removeRunDependency('flb-storage-restore');
        });
    }
    catch (error) {
        abort('Unable to mount browser storage: ' + error);
    }
});

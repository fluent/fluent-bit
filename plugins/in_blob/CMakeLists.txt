# FIXME: there is something wrong when linking objects and this
# static plugin, I should not require to link to a specific symbol
# if the object was already linked from fluent-bit core on src/, also
# jsmn should not be required.

set(src
  blob.c
  blob_db.c
  blob_file.c
  )

FLB_PLUGIN(in_blob "${src}" "")

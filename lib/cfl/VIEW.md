# CFL map views

> **Experimental.** Names, layouts, and semantics in `cfl_view.h` can change in
> any release until this notice is removed. Do not rely on binary compatibility
> across CFL versions.

`cfl_view` is a performance optimization for high-load environments where
transforming key/value data is on the hot path. It gives the logical interface
of a string-keyed map over data that stays where it already is: the bytes it
arrived in, another library's objects, or a native `cfl_kvlist`. A view lets
code look up, rename, remove, replace, and add pairs without first building a
CFL object for every key and value.

Views do not replace `cfl_kvlist`. A view can always be materialized into a
kvlist, and the normal CFL containers remain the right choice when the data
already lives in them or has to outlive its source.

## When to use a view

A view is a good fit when:

- the transformation runs at a high rate and its cost has to be kept low;
- the data arrives in a serialized format and is written back to one;
- only a few pairs of each map are read or changed;
- the source data stays valid and unmodified while it is processed;
- the same code should run over more than one source format.

A typical case is a telemetry pipeline that receives a batch of records,
applies a rename or an insert to each record's attributes, and re-encodes the
batch. With a kvlist every attribute of every record becomes a heap pair, a
key string, and a variant. With a view the untouched attributes are never
decoded.

Keep `cfl_kvlist` when throughput is not a concern, when the data has no
stable source buffer, when most values are read as CFL objects anyway, or when
the map is long-lived.

## How views differ from referenced values

CFL variants can already borrow their payload: `cfl_variant_create_from_string_s()`
and `cfl_variant_create_from_bytes()` take a `referenced` flag that skips the
copy of the string or bytes. Views and referenced values both avoid copying
value bytes, but they remove different costs.

| | Referenced values | Views |
| --- | --- | --- |
| String and bytes payload | Borrowed | Borrowed |
| Key | Copied into a new string for each pair | Borrowed |
| Objects per pair | One `cfl_kvpair` and one `cfl_variant` | None; one slot in a reusable table |
| Values that are never read | Decoded and wrapped in a variant | Not decoded |
| Numbers, booleans, nested data | Full objects | Built only when read or materialized |
| Edits | Change the object graph | Recorded as an overlay on the entry table |

A referenced value still allocates and links a pair and a variant for every
attribute. When a transformation touches one or two keys of each map, that
per-pair work is most of the cost, and it is the part a view removes. The two
also combine: a kvlist built with referenced values can be loaded into a view
like any other kvlist.

## Model

A view is a table of entries, one per pair, kept in order.

| Entry origin | Meaning | Value lives in |
| --- | --- | --- |
| `CFL_VIEW_ENTRY_SOURCE` | A pair of the original data | The source data, reached through the backend |
| `CFL_VIEW_ENTRY_LITERAL` | A scalar set through the view | The entry |
| `CFL_VIEW_ENTRY_VARIANT` | A CFL object set through the view | A `cfl_variant` owned by the view |

The code that owns the data is the *backend*. It loads one entry per pair,
giving a borrowed key and an opaque handle (an index or a pointer). Values are
not decoded at load time. Key lookups and edits then run on the entry table
without calling the backend.

The original data is never written. The entry table works as a copy-on-write
overlay: a removed pair has no entry, a renamed pair is a source entry with
`key_changed` set, and a replaced value turns its entry into a literal or
variant entry.

## Public API

Include the interface directly, or through `<cfl/cfl.h>`:

```c
#include <cfl/cfl_view.h>
```

### Lifecycle

```c
void cfl_view_init(struct cfl_view *view);
void cfl_view_destroy(struct cfl_view *view);
int cfl_view_reserve(struct cfl_view *view, size_t capacity);
void cfl_view_reset(struct cfl_view *view,
                    const struct cfl_view_backend *backend, void *context);
```

A view is a plain structure, usually embedded in its owner or placed on the
stack. `cfl_view_init()` prepares it and `cfl_view_destroy()` releases
everything it owns. `cfl_view_reset()` starts a new load and keeps the entry
table allocation, so one view serves many maps without allocating again.

### Reading

```c
size_t cfl_view_count(const struct cfl_view *view);
const struct cfl_view_entry *cfl_view_entry_at(const struct cfl_view *view,
                                               size_t index);
int64_t cfl_view_find(const struct cfl_view *view,
                      const char *key, size_t key_size);
int64_t cfl_view_find_ex(const struct cfl_view *view,
                         const char *key, size_t key_size,
                         enum cfl_kvlist_match_mode mode);
int cfl_view_value_at(struct cfl_view *view, size_t index,
                      struct cfl_view_value *out);
int cfl_view_get(struct cfl_view *view, const char *key, size_t key_size,
                 struct cfl_view_value *out);
```

`cfl_view_find()` returns the position of the first pair with exactly that key,
or `-1`. It compares bytes. This differs from `cfl_kvlist_fetch()`, which
ignores ASCII case; use `cfl_view_find_ex()` with
`CFL_KVLIST_MATCH_CASE_INSENSITIVE` for that behavior.

`cfl_view_value_at()` fills a `cfl_view_value`: a `CFL_VARIANT_*` type and the
value itself. Scalars are returned in place without allocating. Strings and
bytes are borrowed as a `cfl_view_ref` (pointer and size) and are not
NUL-terminated. For arrays and kvlists, `data.as_variant` is the CFL object
when the view or its backend holds one, and `NULL` when the container only
exists in the source format; materialize it to read its content.

`cfl_view_get()` combines both and returns `1` when the key is found, `0` when
it is missing, and `-1` when the value cannot be read.

### Editing

```c
int cfl_view_append(struct cfl_view *view, const char *key, size_t key_size,
                    const struct cfl_view_value *value);
int cfl_view_set_at(struct cfl_view *view, size_t index,
                    const struct cfl_view_value *value);
int cfl_view_rename_at(struct cfl_view *view, size_t index,
                       const char *key, size_t key_size);
int cfl_view_remove_at(struct cfl_view *view, size_t index);
```

Typed helpers wrap the first two for each scalar type:

| Append | Replace |
| --- | --- |
| `cfl_view_append_string()` | `cfl_view_set_string_at()` |
| `cfl_view_append_bytes()` | `cfl_view_set_bytes_at()` |
| `cfl_view_append_bool()` | `cfl_view_set_bool_at()` |
| `cfl_view_append_int64()` | `cfl_view_set_int64_at()` |
| `cfl_view_append_uint64()` | `cfl_view_set_uint64_at()` |
| `cfl_view_append_double()` | `cfl_view_set_double_at()` |
| `cfl_view_append_null()` | `cfl_view_set_null_at()` |

Arrays, kvlists, and any existing `cfl_variant` go through the object calls:

```c
int cfl_view_append_variant(struct cfl_view *view,
                            const char *key, size_t key_size,
                            struct cfl_variant *value);
int cfl_view_set_variant_at(struct cfl_view *view, size_t index,
                            struct cfl_variant *value);
int cfl_view_append_array(struct cfl_view *view,
                          const char *key, size_t key_size,
                          struct cfl_array *value);
int cfl_view_append_kvlist(struct cfl_view *view,
                           const char *key, size_t key_size,
                           struct cfl_kvlist *value);
```

Every edit returns `0` on success and `-1` on failure, and a failed edit leaves
the view as it was. Append does not check for duplicate keys; use
`cfl_view_find()` first when the key must be unique. Removing a pair shifts the
positions of the pairs after it.

### Materializing

```c
struct cfl_kvlist *cfl_view_materialize(struct cfl_view *view);
struct cfl_kvlist *cfl_view_materialize_in(struct cfl_view *view,
                                           struct cfl_arena *arena);
struct cfl_variant *cfl_view_materialize_at(struct cfl_view *view, size_t index);
```

These build native CFL objects from the current content of the view, edits
included. The results belong to the caller and are independent of the view and
of the source data. `cfl_view_materialize_in()` allocates from an arena, and
`cfl_view_materialize_at()` builds one heap variant from one value.

## Ownership and lifetime

- **Source data.** A view does not own the data it describes. The owner keeps
  it valid and unmodified from the load until the view is reset, reloaded, or
  destroyed.
- **Keys and values passed to edits.** By default they are borrowed and must
  stay valid until the view is reset. This is the cheapest mode and fits
  callers whose keys and values come from long-lived configuration.
- **Copy mode.** After `cfl_view_copy_set(view, CFL_TRUE)` the view copies the
  keys and the string or bytes values it receives into its own storage. The
  copies are released on reset, and the storage is reused across loads.
  `cfl_view_store()` copies arbitrary bytes into the same storage.
- **Variants.** The view takes ownership of a variant passed to
  `cfl_view_append_variant()` or `cfl_view_set_variant_at()` when the call
  succeeds, and destroys it when the pair is removed or replaced, or when the
  view is reset. The variant must not already belong to a container. An arena
  variant is accepted as long as its arena outlives the entry.
- **Threads.** A view is not thread-safe. It can move between threads only
  together with its data, and never while a call is using it.

```c
struct cfl_view view;
char buffer[64];
int length;

cfl_view_init(&view);
cfl_view_copy_set(&view, CFL_TRUE);
if (cfl_view_kvlist_load(&view, attributes) != 0) {
    cfl_view_destroy(&view);
    return -1;
}

/* 'buffer' can be reused immediately: the view holds its own copy */
length = snprintf(buffer, sizeof(buffer), "pod-%d", pod_index);
if (cfl_view_append_string(&view, "k8s.pod.name", 12, buffer, (size_t) length) != 0) {
    cfl_view_destroy(&view);
    return -1;
}
```

## Native kvlist backend

CFL ships a backend for its own containers, so the same view code runs over a
kvlist:

```c
int cfl_view_kvlist_load(struct cfl_view *view, struct cfl_kvlist *kvlist);
int cfl_view_kvlist_commit(struct cfl_view *view);
```

`cfl_view_kvlist_load()` borrows the keys and values of the list.
`cfl_view_kvlist_commit()` writes the edits back to the same list: removed
pairs are destroyed, renamed pairs get the new key, and added or replaced
pairs are created at the position they have in the view. Variants owned by the
view move into the list, or are copied when the list uses a different
allocator. After a successful commit every entry is a source entry again, so
the view can keep being used.

A commit fails only when an allocation fails. The list can then hold part of
the edits, including both the old and the new pair of a replaced value. The
list and the view stay valid.

```c
struct cfl_view view;
int64_t position;
int result;

cfl_view_init(&view);
result = cfl_view_kvlist_load(&view, attributes);

if (result == 0) {
    position = cfl_view_find(&view, "http.url", 8);
    if (position >= 0) {
        result = cfl_view_rename_at(&view, (size_t) position, "url.full", 8);
    }
}
if (result == 0 && cfl_view_find(&view, "team", 4) < 0) {
    result = cfl_view_append_string(&view, "team", 4, "store", 5);
}

/* a failed edit leaves the list as it was: nothing is committed */
if (result == 0) {
    result = cfl_view_kvlist_commit(&view);
}
cfl_view_destroy(&view);

return result;
```

## Writing a backend

A backend describes a data source through two optional callbacks:

```c
struct cfl_view_backend {
    const char *name;
    int (*value) (struct cfl_view *view, const struct cfl_view_entry *entry,
                  struct cfl_view_value *out);
    struct cfl_variant *(*materialize) (struct cfl_view *view,
                                        const struct cfl_view_entry *entry);
};
```

- `value` reads a source value without allocating. `out` arrives zeroed. For a
  container it sets only the type, unless a CFL object already exists.
- `materialize` builds an owned heap variant from a source value, including
  nested data.

Both receive source entries only. A callback left `NULL` makes the matching
calls fail for source entries; keys, edits, and literal values keep working.

Loading is a loop over the pairs of the source:

```c
struct record {
    const char **keys;
    const char **values;
    size_t count;
};

static int record_value(struct cfl_view *view,
                        const struct cfl_view_entry *entry,
                        struct cfl_view_value *out)
{
    struct record *record = view->context;

    out->type = CFL_VARIANT_STRING;
    out->data.as_bytes.data = record->values[entry->source.index];
    out->data.as_bytes.size = strlen(record->values[entry->source.index]);

    return 0;
}

static const struct cfl_view_backend record_backend = {
    "record", record_value, NULL
};

static int record_load(struct cfl_view *view, struct record *record)
{
    size_t index;

    cfl_view_reset(view, &record_backend, record);
    for (index = 0; index < record->count; index++) {
        if (cfl_view_load_index(view, record->keys[index],
                                strlen(record->keys[index]),
                                (int64_t) index) != 0) {
            return -1;
        }
    }

    return 0;
}
```

`cfl_view_load_index()` and `cfl_view_load_pointer()` store the handle the
backend needs to find the pair again. Each entry also has a `cache` reference
reserved for the backend, for example to remember where a value starts in a
wire buffer.

## Writing an encoder

Code that serializes a view walks the entry table in order. This is the
contract an encoder can rely on:

1. `cfl_view_count()` and `cfl_view_entry_at()` give every live pair once, in
   order. Removed pairs are not present.
2. `entry->key` is always the current key, whatever the origin.
3. `cfl_view_value_at()` returns every scalar in place.
4. For an array or kvlist, `data.as_variant` is used when it is not `NULL`;
   otherwise `cfl_view_materialize_at()` builds the object and the encoder
   destroys it afterwards.

```c
static int encode_view(struct cfl_view *view, struct encoder *encoder)
{
    size_t index;
    struct cfl_view_value value;
    struct cfl_variant *object;
    const struct cfl_view_entry *entry;

    for (index = 0; index < cfl_view_count(view); index++) {
        entry = cfl_view_entry_at(view, index);
        if (cfl_view_value_at(view, index, &value) != 0) {
            return -1;
        }
        encode_key(encoder, entry->key.data, entry->key.size);

        if (value.type != CFL_VARIANT_ARRAY && value.type != CFL_VARIANT_KVLIST) {
            encode_scalar(encoder, &value);
        }
        else if (value.data.as_variant != NULL) {
            encode_object(encoder, value.data.as_variant);
        }
        else {
            object = cfl_view_materialize_at(view, index);
            if (object == NULL) {
                return -1;
            }
            encode_object(encoder, object);
            cfl_variant_destroy(object);
        }
    }

    return 0;
}
```

An encoder that knows the backend can do better than this generic walk. When
the source and target formats match, an unmodified source entry
(`origin == CFL_VIEW_ENTRY_SOURCE` and `key_changed == 0`) can be copied as a
raw span, and `cfl_view_modified()` tells whether the whole map can be copied
unchanged.

## Limits

- Lookups are linear. Views target maps with tens of pairs, like telemetry
  attributes; they are not an index.
- Nested maps are not views. Reading inside a container that has no CFL object
  means materializing it.
- There is no generic commit for backends other than the kvlist one. Writing
  the result back is the job of the encoder that knows the target format.
- The view does not detect duplicate keys; the first match wins on lookup.

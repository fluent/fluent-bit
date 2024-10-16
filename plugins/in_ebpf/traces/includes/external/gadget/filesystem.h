// Based on
// https://github.com/aquasecurity/tracee/blob/bd80c1d9e69e275f06810f2a0f99414aced14fa8/pkg/ebpf/c/common/filesystem.h

#ifndef __COMMON_FILESYSTEM_H__
#define __COMMON_FILESYSTEM_H__

// clang-format off
#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define MAX_STRING_SIZE    4096       // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE 4096       // max size of bytes array (arbitrarily chosen)
#define MAX_STR_FILTER_SIZE 16        // bounded to size of the compared values (comm)
#define MAX_BIN_PATH_SIZE   256       // max binary path size
#define FILE_MAGIC_HDR_SIZE 32        // magic_write: bytes to save from a file's header
#define FILE_MAGIC_MASK     31        // magic_write: mask used for verifier boundaries
#define NET_SEQ_OPS_SIZE    4         // print_net_seq_ops: struct size - TODO: replace with uprobe argument
#define NET_SEQ_OPS_TYPES   6         // print_net_seq_ops: argument size - TODO: replace with uprobe argument
#define MAX_KSYM_NAME_SIZE  64
#define UPROBE_MAGIC_NUMBER 20220829
#define ARGS_BUF_SIZE       32000
#define SEND_META_SIZE      24
#define MAX_MEM_DUMP_SIZE   127

#define MAX_PATH_COMPONENTS   80

// memory related
enum buf_idx_e
{
	STRING_BUF_IDX,
	//FILE_BUF_IDX,
	MAX_BUFFERS
};

typedef struct simple_buf {
	u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
	struct {                                                                                       \
		__uint(type, _type);                                                                       \
		__uint(max_entries, _max_entries);                                                         \
		__type(key, _key_type);                                                                    \
		__type(value, _value_type);                                                                \
	} _name SEC(".maps");


#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                                         \
	BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);                        // percpu global buffer variables

// undef as we don't want to use this in our gadgets. yet?
#undef BPF_MAP
#undef BPF_PERCPU_ARRAY

static __always_inline buf_t *get_buf(int idx)
{
	return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
	return BPF_CORE_READ(vfsmnt, mnt_root);
}

static __always_inline struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
	return BPF_CORE_READ(dentry, d_parent);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
	return BPF_CORE_READ(dentry, d_name);
}

static __always_inline void *get_path_str(struct path *path)
{
	struct path f_path;
	bpf_probe_read(&f_path, sizeof(struct path), path);
	char slash = '/';
	int zero = 0;
	struct dentry *dentry = f_path.dentry;
	struct vfsmount *vfsmnt = f_path.mnt;
	struct mount *mnt_parent_p;

	struct mount *mnt_p = real_mount(vfsmnt);
	bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

	u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
	struct dentry *mnt_root;
	struct dentry *d_parent;
	struct qstr d_name;
	unsigned int len;
	unsigned int off;
	int sz;

	// Get per-cpu string buffer
	buf_t *string_p = get_buf(STRING_BUF_IDX);
	if (string_p == NULL)
		return NULL;

#pragma unroll
	for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
		mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
		d_parent = get_d_parent_ptr_from_dentry(dentry);
		if (dentry == mnt_root || dentry == d_parent) {
			if (dentry != mnt_root) {
				// We reached root, but not mount root - escaped?
				break;
			}
			if (mnt_p != mnt_parent_p) {
				// We reached root, but not global root - continue with mount point path
				bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
				bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
				bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
				vfsmnt = &mnt_p->mnt;
				continue;
			}
			// Global root - path fully parsed
			break;
		}
		// Add this dentry name to path
		d_name = get_d_name_from_dentry(dentry);
		len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
		off = buf_off - len;

		// Is string buffer big enough for dentry name?
		sz = 0;
		if (off <= buf_off) { // verify no wrap occurred
			len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
			sz = bpf_probe_read_str(
				&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
		} else
			break;
		if (sz > 1) {
			buf_off -= 1; // remove null byte termination with slash sign
			bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
			buf_off -= sz - 1;
		} else {
			// If sz is 0 or 1 we have an error (path can't be null nor an empty string)
			break;
		}
		dentry = d_parent;
	}

	if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
		// memfd files have no path in the filesystem -> extract their name
		buf_off = 0;
		d_name = get_d_name_from_dentry(dentry);
		bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
	} else {
		// Add leading slash
		buf_off -= 1;
		bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
		// Null terminate the path string
		bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
	}

	return &string_p->buf[buf_off];
}

// Function to extract file structure from a user space file descriptor
static __always_inline struct file * get_struct_file_for_fd(int fd_num)
{
	if (fd_num < 0) {
		return NULL;
	}

	struct task_struct *task = (struct task_struct *) bpf_get_current_task();
	if (task == NULL) {
		return NULL;
	}

	// extract the file vector from the task_struct
	struct file **fd = BPF_CORE_READ(task, files, fdt, fd);

	// extract the file pointer from the file vector
	struct file *f = NULL;
	uint max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
	if (fd_num < max_fds) {
		bpf_core_read((void *) &f, sizeof(f), &fd[fd_num]);
	}

	return f;
}

static __always_inline long read_full_path_of_open_file_fd(int fd_num, char *buf, u64 buf_len)
{
	struct file *file = get_struct_file_for_fd(fd_num);
	if (file == NULL) {
		return -1;
	}

	struct path f_path = BPF_CORE_READ(file, f_path);

	// Extract the full path string
	char* c_path = get_path_str(&f_path);
	if (!c_path) {
		return -1;
	}
	return bpf_probe_read_kernel_str(buf, buf_len, c_path);
}

#endif

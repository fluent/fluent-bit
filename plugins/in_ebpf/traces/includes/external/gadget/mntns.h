/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef MNTNS_H
#define MNTNS_H

#include <gadget/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// gadget_get_mntns_id returns the mntns_id of the current task.
static __always_inline gadget_mntns_id gadget_get_mntns_id()
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

#endif

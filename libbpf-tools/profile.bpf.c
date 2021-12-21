// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on tcpconnect(8) from BCC by Brendan Gregg
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "profile.h"

#define MAX_ENTRIES		10240

const volatile pid_t targ_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
	// __uint(map_flags, BPF_F_NO_PREALLOC);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#25-mapget_stackid

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    __u64 *val;
    static __u64 zero;
    key.tgid =  bpf_get_current_pid_tgid();
    key.pid = bpf_get_current_pid_tgid() >> 32;
    if (targ_tgid != -1 && targ_tgid != key.pid)
        return 0;

    bpf_get_current_comm(key.name, sizeof(key.name));

    key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);

    val = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

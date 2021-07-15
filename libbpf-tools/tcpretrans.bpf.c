// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
// Copyright (c) 2021 Red Hat
//
// Based on tcpconnect.c by Anton Protopopov and
// tcpretrans(8) from BCC by Brendan Gregg
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "tcpretrans.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tp/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb* ctx) {

	struct event e = {};
	const struct sock *skp;
	__u16 dport;
	__u16 sport;
	__u32 family;
	__u64 pid_tgid;
	__u32 pid;
	int state;

	e.type = RETRANSMIT;
	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	e.pid = pid;

	skp = BPF_CORE_READ(ctx, skaddr);
	family = BPF_CORE_READ(skp, __sk_common.skc_family);
	e.af = family;

	// tcp_event_sk_skb.dport and .sport already in host byte order
	BPF_CORE_READ_INTO(&dport, ctx, dport);
	e.dport = dport;
	BPF_CORE_READ_INTO(&sport, ctx, sport);
	e.sport = sport;
	state = BPF_CORE_READ(ctx, state);
	e.state = state;

	if (family == AF_INET) {
		e.saddr_v4 = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
		e.daddr_v4 = BPF_CORE_READ(skp, __sk_common.skc_daddr);

	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(e.saddr_v6, skp,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(e.daddr_v6, skp,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
				  &e, sizeof(e));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

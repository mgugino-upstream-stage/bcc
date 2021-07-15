// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
// Copyright (c) 2021 Red Hat, Inc.
#ifndef __TCPRETRANS_H
#define __TCPRETRANS_H

#define RETRANSMIT  1
#define TLP         2

struct event {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	__u32 af; // AF_INET or AF_INET6
	__u32 pid;
	__u16 dport;
	__u16 sport;
	__u64 type;
	int state;
};

#endif /* __TCPRETRANS_H */

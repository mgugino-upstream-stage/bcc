// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
// Copyright (c) 2021 Red Hat, Inc.
//
// Based on tcpconnect.c by Anton Protopopov and
// tcpretrans(8) from BCC by Brendan Gregg
#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "tcpretrans 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\ntcpretrans: Trace TCP retransmits\n"
	"\n"
	"EXAMPLES:\n"
	"    tcpretrans             # display all TCP retransmissions\n"
	// TODO "    tcpconnect -c          # count occurred retransmits per flow\n"
	// TODO "    tcpconnect -l      	# include tail loss probe attempts\n"
	;

const char* TCPSTATE[] = {
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
	"NEW_SYN_RECV"};


static volatile sig_atomic_t hang_on = 1;

static void sig_int(int signo)
{
	hang_on = 0;
}

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "count", 'c', NULL, 0, "Count connects per src ip and dst ip/port" },
	{ "lossprobe", 'l', NULL, 0, "include tail loss probe attempts" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static struct env {
	bool verbose;
	bool count;
	bool lossprobe;
} env = {};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		env.count = true;
		break;
	case 'l':
		env.lossprobe = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_events_header()
{
	printf("%-8s %-6s %-2s %-20s %1s> %-20s %-4s\n", "TIME", "PID", "IP",
		"LADDR:LPORT", "T", "RADDR:RPORT", "STATE");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char src[INET6_ADDRSTRLEN+6];
	char dst[INET6_ADDRSTRLEN+6];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event->af=%d", e->af);
		return;
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	char remote[INET6_ADDRSTRLEN + 6];
	char local[INET6_ADDRSTRLEN + 6];
	sprintf(local, "%s:%d", inet_ntop(e->af, &s, src, sizeof(src)), e->sport);
	sprintf(remote, "%s:%d", inet_ntop(e->af, &d, src, sizeof(dst)), e->dport);

	printf("%-8s %-6d %-2d %-20s %1s> %-20s %s\n",
		   ts,
		   e->pid,
		   e->af == AF_INET ? 4 : 6,
		   local,
		   e->type == RETRANSMIT ? "R" : "L",
		   remote,
		   TCPSTATE[e->state - 1]);
	return;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void print_events(int perf_map_fd)
{
	struct perf_buffer_opts pb_opts = {
		.sample_cb = handle_event,
		.lost_cb = handle_lost_events,
	};
	struct perf_buffer *pb = NULL;
	int err;

	pb = perf_buffer__new(perf_map_fd, 128, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	print_events_header();
	while (hang_on) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && errno != EINTR) {
			warn("Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	perf_buffer__free(pb);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = NULL,
	};

	struct ring_buffer *rb = NULL;
	struct tcpretrans_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.count || env.lossprobe) {
		warn("count and lossprobe options not yet implemented");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %s\n", strerror(errno));
		return 1;
	}

	obj = tcpretrans_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	err = tcpretrans_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpretrans_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	print_events(bpf_map__fd(obj->maps.events));

cleanup:
	ring_buffer__free(rb);
	tcpretrans_bpf__destroy(obj);

	return err != 0;
}

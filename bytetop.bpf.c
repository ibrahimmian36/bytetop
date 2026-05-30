// SPDX-License-Identifier: GPL-2.0
/*
 * bytetop — per-process, per-destination TCP byte accounting.
 *
 * Three hooks:
 *   tp_btf/inet_sock_set_state   — lifecycle: track new conns at
 *                                  TCP_ESTABLISHED, reap at TCP_CLOSE.
 *   fentry/tcp_sendmsg           — count bytes sent + fix pid to the
 *                                  actually-sending process (app ctx).
 *   fentry/tcp_cleanup_rbuf      — count bytes that userspace read off
 *                                  the receive queue.
 *
 * One HASH map keyed by sock pointer holds per-conn cumulative byte
 * totals and metadata. One RINGBUF carries OPEN / BYTES / CLOSE events
 * to userspace. BYTES events are emitted on a 64 KiB threshold per
 * direction, so an idle conn produces ~no events while a busy one
 * produces ~one event per 64 KiB transferred.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET   2
#define AF_INET6 10

#define TCP_ESTABLISHED 1
#define TCP_CLOSE       7

#define EVT_OPEN  0
#define EVT_BYTES 1
#define EVT_CLOSE 2

#define BYTES_EMIT_THRESHOLD (64 * 1024)   /* 64 KiB */
#define MAX_TRACKED          (1 << 16)     /* 65536 sockets */

#define FLAG_OPEN_EMITTED  (1 << 0)
#define FLAG_PID_REAL      (1 << 1)

char LICENSE[] SEC("license") = "GPL";

/* ---- per-conn state ------------------------------------------------ */
struct conn_info {
    __u64 ts_open_ns;
    __u32 pid;
    __u8  family;
    __u8  flags;
    __u16 sport;            /* host order */
    __u16 dport;            /* host order */
    __u8  _pad[2];
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[16];
    __u64 bytes_tx;         /* cumulative since first observed */
    __u64 bytes_rx;
    __u64 emitted_tx;       /* last value at which we emitted a BYTES event */
    __u64 emitted_rx;
};

/* ---- userspace event shape ----------------------------------------- */
struct conn_evt {
    __u8  kind;             /* EVT_OPEN | EVT_BYTES | EVT_CLOSE */
    __u8  family;           /* AF_INET | AF_INET6 */
    __u8  _pad0[2];
    __u32 pid;
    __u64 sk;               /* sock pointer = conn identity */
    __u64 ts_ns;
    __u64 bytes_tx;         /* cumulative at emission time */
    __u64 bytes_rx;
    __u64 delta_tx;         /* bytes since last BYTES event (OPEN/CLOSE: 0) */
    __u64 delta_rx;
    __u16 sport;            /* host order */
    __u16 dport;
    __u8  _pad1[4];
    char  comm[16];
    __u8  saddr[16];        /* IPv4: first 4 bytes, rest zero. IPv6: full 16 */
    __u8  daddr[16];
};

/* Anchor so the struct survives BTF emission and JS can decode it. */
__attribute__((used)) static const struct conn_evt __conn_evt_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED);
    __type(key,   __u64);
    __type(value, struct conn_info);
} conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);   /* 256 KiB */
} events SEC(".maps");

/* ---- helpers ------------------------------------------------------- */

/* Is the given comm a kernel-thread-ish name we should NOT lock in as
 * the real socket owner? TCP state transitions often fire from softirq,
 * where current is whatever happened to be running — usually swapper
 * or a kworker. We refuse those and let a later tcp_sendmsg (which
 * runs in true app context) update us with the real owner. */
static __always_inline int is_kernel_comm(const char *c) {
    if (c[0] == 's' && c[1] == 'w' && c[2] == 'a' && c[3] == 'p') return 1;
    if (c[0] == 'k' && c[1] == 'w' && c[2] == 'o' && c[3] == 'r') return 1;
    if (c[0] == 'k' && c[1] == 's' && c[2] == 'o' && c[3] == 'f') return 1;
    return 0;
}

/* Read addrs/ports/family off the sock. v4 puts the 32-bit address in
 * the first 4 bytes of the 16-byte buffer; the rest stays zero. */
static __always_inline void fill_addrs(struct sock *sk, struct conn_info *ci) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    ci->family = (__u8)family;
    ci->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
    ci->dport  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    __builtin_memset(ci->saddr, 0, sizeof(ci->saddr));
    __builtin_memset(ci->daddr, 0, sizeof(ci->daddr));

    if (family == AF_INET) {
        __be32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(ci->saddr, &s4, 4);
        __builtin_memcpy(ci->daddr, &d4, 4);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&ci->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&ci->daddr, sk, __sk_common.skc_v6_daddr);
    }
}

/* Copy a conn_info snapshot into a ringbuf event slot. */
static __always_inline void fill_evt(struct conn_evt *e, struct sock *sk,
                                     struct conn_info *ci, __u8 kind) {
    __builtin_memset(e, 0, sizeof(*e));
    e->kind     = kind;
    e->family   = ci->family;
    e->pid      = ci->pid;
    e->sk       = (__u64)sk;
    e->ts_ns    = bpf_ktime_get_ns();
    e->bytes_tx = ci->bytes_tx;
    e->bytes_rx = ci->bytes_rx;
    e->sport    = ci->sport;
    e->dport    = ci->dport;
    __builtin_memcpy(e->comm,  ci->comm,  sizeof(e->comm));
    __builtin_memcpy(e->saddr, ci->saddr, sizeof(e->saddr));
    __builtin_memcpy(e->daddr, ci->daddr, sizeof(e->daddr));
}

/* ---- lifecycle (state transitions) -------------------------------- */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_set_state, struct sock *sk, int oldstate, int newstate) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return 0;

    __u64 key = (__u64)sk;

    if (newstate == TCP_ESTABLISHED) {
        struct conn_info *existing = bpf_map_lookup_elem(&conns, &key);
        if (existing) return 0;       /* already tracked */

        struct conn_info ci = {};
        ci.ts_open_ns = bpf_ktime_get_ns();

        /* Best-effort pid: ESTABLISHED for outbound fires in app context
         * (the connecting task) when SYN+ACK arrives via softirq is the
         * common case — meaning we'll often get a kworker here. We grab
         * whatever current is, and tcp_sendmsg fixes us up on the first
         * send from the real owner. */
        __u64 pt = bpf_get_current_pid_tgid();
        ci.pid = pt >> 32;
        bpf_get_current_comm(ci.comm, sizeof(ci.comm));
        if (!is_kernel_comm(ci.comm)) ci.flags |= FLAG_PID_REAL;

        fill_addrs(sk, &ci);
        bpf_map_update_elem(&conns, &key, &ci, BPF_ANY);
        return 0;
    }

    if (newstate == TCP_CLOSE) {
        struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
        if (!ci) return 0;

        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            bpf_map_delete_elem(&conns, &key);
            return 0;
        }
        fill_evt(e, sk, ci, EVT_CLOSE);
        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&conns, &key);
        return 0;
    }

    return 0;
}

/* ---- bytes sent --------------------------------------------------- */
/* tcp_sendmsg(sk, msg, size) — fires for every app send() / write() on
 * a TCP socket, in the calling-process context. Perfect for pid fixup
 * and tx counting. We don't read msg at all; size is the byte count. */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_sendmsg, struct sock *sk, struct msghdr *msg, __u64 size) {
    if (size == 0) return 0;
    __u64 key = (__u64)sk;
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
    if (!ci) return 0;                /* not tracked (created before bytetop started) */

    /* fix pid to the real sender if we haven't already */
    if (!(ci->flags & FLAG_PID_REAL)) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        if (!is_kernel_comm(comm)) {
            __u64 pt = bpf_get_current_pid_tgid();
            ci->pid = pt >> 32;
            __builtin_memcpy(ci->comm, comm, sizeof(ci->comm));
            ci->flags |= FLAG_PID_REAL;
        }
    }

    ci->bytes_tx += size;

    /* emit OPEN deferred until we have a real owner — that way the
     * "new connection from X to Y" event the user sees actually
     * names X correctly. */
    if (!(ci->flags & FLAG_OPEN_EMITTED) && (ci->flags & FLAG_PID_REAL)) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_OPEN);
            bpf_ringbuf_submit(e, 0);
        }
        ci->flags |= FLAG_OPEN_EMITTED;
    }

    /* threshold-emit a BYTES event so userspace sees the flow */
    __u64 dtx = ci->bytes_tx - ci->emitted_tx;
    if (dtx >= BYTES_EMIT_THRESHOLD) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_BYTES);
            e->delta_tx = dtx;
            e->delta_rx = ci->bytes_rx - ci->emitted_rx;
            ci->emitted_tx = ci->bytes_tx;
            ci->emitted_rx = ci->bytes_rx;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

/* ---- bytes received ----------------------------------------------- */
/* tcp_cleanup_rbuf(sk, copied) fires after userspace reads `copied`
 * bytes off the receive queue. Reliable account of bytes that actually
 * reached the app. Also a good place to fix attribution for receive-
 * only flows (servers reading inbound requests before responding) —
 * we mirror the tcp_sendmsg pid-fixup logic here. */
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(on_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    __u64 key = (__u64)sk;
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
    if (!ci) return 0;

    /* fix pid to the real receiver if we haven't already — this also
     * works in softirq context (tcp_cleanup_rbuf can fire from there),
     * because is_kernel_comm refuses kworker/swapper/ksoftirqd names. */
    if (!(ci->flags & FLAG_PID_REAL)) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        if (!is_kernel_comm(comm)) {
            __u64 pt = bpf_get_current_pid_tgid();
            ci->pid = pt >> 32;
            __builtin_memcpy(ci->comm, comm, sizeof(ci->comm));
            ci->flags |= FLAG_PID_REAL;
        }
    }

    ci->bytes_rx += (__u64)copied;

    /* emit OPEN deferred until we have a real owner — same deferred
     * logic as in tcp_sendmsg, so receive-only flows are also visible
     * in the live event feed with correct attribution. */
    if (!(ci->flags & FLAG_OPEN_EMITTED) && (ci->flags & FLAG_PID_REAL)) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_OPEN);
            bpf_ringbuf_submit(e, 0);
        }
        ci->flags |= FLAG_OPEN_EMITTED;
    }

    __u64 drx = ci->bytes_rx - ci->emitted_rx;
    if (drx >= BYTES_EMIT_THRESHOLD) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_BYTES);
            e->delta_tx = ci->bytes_tx - ci->emitted_tx;
            e->delta_rx = drx;
            ci->emitted_tx = ci->bytes_tx;
            ci->emitted_rx = ci->bytes_rx;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

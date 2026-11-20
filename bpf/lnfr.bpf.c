#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LNFR_RING_BYTES (256 * 1024)
#define NS_PER_SECOND 1000000000ULL
#define LNFR_AF_INET 2
#define LNFR_AF_INET6 10
#define LNFR_IPPROTO_TCP 6
#define LNFR_CONNECT_LIMIT 1024
#define LNFR_SKB_DST_NOREF 1UL

enum event_kind {
    SOCKET_STATE = 1,
    TCP_CONNECT,
    TCP_ACCEPT,
    TCP_RETRANSMIT,
    TC_INGRESS_OBSERVED,
    TC_EGRESS_OBSERVED,
    BRIDGE_FORWARD_OBSERVED,
    ROUTE_FORWARD_OBSERVED,
};

/* Partial kernel types. CO-RE resolves only the fields read by these probes. */
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct trace_event_raw_inet_sock_set_state {
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 protocol;
};

struct trace_event_raw_tcp_retransmit_skb {
    const void *skaddr;
    int state;
    int err;
};

struct ns_common {
    unsigned int inum;
};

struct net {
    struct ns_common ns;
};

typedef struct {
    struct net *net;
} possible_net_t;

typedef struct {
    long long counter;
} atomic64_t;

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    __u16 skc_family;
    int skc_bound_dev_if;
    possible_net_t skc_net;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    atomic64_t skc_cookie;
};

struct sock {
    struct sock_common __sk_common;
    __u16 sk_protocol;
};

struct socket {
    struct sock *sk;
};
struct net_device {
    int ifindex;
    possible_net_t nd_net;
};

struct sk_buff {
    struct net_device *dev;
    unsigned int len;
    __u16 mac_header;
    __u16 network_header;
    unsigned long _skb_refdst;
    unsigned int tail;
    unsigned char *head;
};

struct dst_entry {
    struct net_device *dev;
};

struct net_bridge {
    struct net_device *dev;
};

struct net_bridge_port {
    struct net_bridge *br;
    struct net_device *dev;
};
#pragma clang attribute pop

struct sockaddr_unsized;
struct proto_accept_arg;

struct tcp_event_v2 {
    __u64 monotonic_ns;
    __u64 context_cgroup_id;
    __u64 socket_cookie;
    __u64 connect_elapsed_ns;
    __u32 cpu;
    __u32 context_tgid;
    __u32 context_tid;
    __u32 netns_inum;
    union { __s32 oldstate; __u32 tcp_flags; __u32 ingress_ifindex; };
    union { __s32 newstate; __u32 bridge_ifindex; __u32 hop_limit; };
    union { __s32 result; __u32 skb_len; };
    union { __u16 family; __u16 ether_type; };
    __u16 local_port;
    __u16 remote_port;
    __u8 schema_version;
    __u8 kind;
    __u8 local_addr[16];
    __u8 remote_addr[16];
    union { __s32 bound_ifindex; __u32 ifindex; };
    __u8 requested_addr[16];
    __u16 requested_port;
    __u16 requested_family;
    union { __u32 reserved; __u32 local_origin; __u32 ip_next_header; };
};

_Static_assert(sizeof(struct tcp_event_v2) == 128, "unexpected event ABI");

struct capture_stats {
    __u64 window_second;
    __u64 window_events;
    __u64 submitted;
    __u64 ring_lost;
    __u64 rate_limited;
    __u64 connect_tracking_lost;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, LNFR_RING_BYTES);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_stats);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LNFR_CONNECT_LIMIT);
    __type(key, __u64);
    __type(value, __u64);
} connect_started SEC(".maps");

const volatile __u32 target_tgid = 0;
const volatile __u32 target_netns = 0;
const volatile __u32 tc_netns = 0;
const volatile __u32 bridge_ifindex = 0;
const volatile __u32 bridge_netns = 0;
const volatile __u32 route_netns = 0;
const volatile __u32 events_per_cpu_per_second = 256;

static __always_inline struct capture_stats *get_stats(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline __u32 socket_netns(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline bool matches_filter(__u64 pid_tgid, __u32 netns)
{
    return (!target_tgid || target_tgid == pid_tgid >> 32) &&
           (!target_netns || target_netns == netns);
}

static __always_inline struct tcp_event_v2 *reserve_record(
    __u16 family, __u32 netns, __u8 kind, struct capture_stats *counts)
{
    if (!counts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 second = now / NS_PER_SECOND;

    if (counts->window_second != second) {
        counts->window_second = second;
        counts->window_events = 0;
    }
    if (counts->window_events >= events_per_cpu_per_second) {
        __sync_fetch_and_add(&counts->rate_limited, 1);
        return 0;
    }
    counts->window_events++;

    struct tcp_event_v2 *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event) {
        __sync_fetch_and_add(&counts->ring_lost, 1);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->monotonic_ns = now;
    event->cpu = bpf_get_smp_processor_id();
    event->netns_inum = netns;
    event->family = family;
    event->schema_version = 2;
    event->kind = kind;
    return event;
}

static __always_inline struct tcp_event_v2 *reserve_event(
    const struct sock *sk, __u64 pid_tgid, __u32 netns, __u8 kind,
    struct capture_stats *counts)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family != LNFR_AF_INET && family != LNFR_AF_INET6)
        return 0;

    struct tcp_event_v2 *event = reserve_record(family, netns, kind, counts);

    if (!event)
        return 0;

    event->context_cgroup_id = bpf_get_current_cgroup_id();
    event->socket_cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    event->context_tgid = pid_tgid >> 32;
    event->context_tid = (__u32)pid_tgid;
    event->oldstate = -1;
    event->newstate = -1;
    event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->bound_ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);

    if (family == LNFR_AF_INET) {
        BPF_CORE_READ_INTO((__be32 *)event->local_addr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO((__be32 *)event->remote_addr, sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO((struct in6_addr *)event->local_addr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO((struct in6_addr *)event->remote_addr, sk, __sk_common.skc_v6_daddr);
    }
    return event;
}

static __always_inline void submit_event(struct tcp_event_v2 *event,
                                         struct capture_stats *counts)
{
    bpf_ringbuf_submit(event, 0);
    __sync_fetch_and_add(&counts->submitted, 1);
}

SEC("tracepoint/sock/inet_sock_set_state")
int on_socket_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    const struct sock *sk = ctx->skaddr;

    if (!sk || ctx->protocol != LNFR_IPPROTO_TCP)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 netns = socket_netns(sk);

    if (!matches_filter(pid_tgid, netns))
        return 0;

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_event(sk, pid_tgid, netns, SOCKET_STATE, counts);

    if (event) {
        event->oldstate = ctx->oldstate;
        event->newstate = ctx->newstate;
        submit_event(event, counts);
    }
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int on_retransmit(struct trace_event_raw_tcp_retransmit_skb *ctx)
{
    const struct sock *sk = ctx->skaddr;

    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 netns = socket_netns(sk);

    if (!matches_filter(pid_tgid, netns))
        return 0;

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_event(sk, pid_tgid, netns, TCP_RETRANSMIT, counts);

    if (event) {
        event->newstate = ctx->state;
        event->result = ctx->err;
        submit_event(event, counts);
    }
    return 0;
}

SEC("fentry/inet_stream_connect")
int BPF_PROG(on_connect_enter, struct socket *socket)
{
    struct sock *sk = BPF_CORE_READ(socket, sk);

    if (!sk || BPF_CORE_READ(sk, sk_protocol) != LNFR_IPPROTO_TCP)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!matches_filter(pid_tgid, socket_netns(sk)))
        return 0;

    __u64 now = bpf_ktime_get_ns();

    if (bpf_map_update_elem(&connect_started, &pid_tgid, &now, BPF_ANY)) {
        struct capture_stats *counts = get_stats();

        if (counts)
            __sync_fetch_and_add(&counts->connect_tracking_lost, 1);
    }
    return 0;
}

/* The connect wrapper takes a kernel sockaddr and its length. */
static __always_inline void read_requested_peer(struct tcp_event_v2 *event,
                                                const void *address, int length)
{
    __u16 family;

    if (!address || length < (int)sizeof(family) ||
        bpf_probe_read_kernel(&family, sizeof(family), address))
        return;

    if (family == LNFR_AF_INET && length >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr;

        if (bpf_probe_read_kernel(&addr, sizeof(addr), address))
            return;
        __builtin_memcpy(event->requested_addr, &addr.sin_addr, sizeof(addr.sin_addr));
        event->requested_port = bpf_ntohs(addr.sin_port);
    } else if (family == LNFR_AF_INET6 &&
               length >= (int)__builtin_offsetof(struct sockaddr_in6, sin6_scope_id)) {
        struct sockaddr_in6 addr;

        if (bpf_probe_read_kernel(&addr, __builtin_offsetof(struct sockaddr_in6, sin6_scope_id),
                                  address))
            return;
        __builtin_memcpy(event->requested_addr, &addr.sin6_addr, sizeof(addr.sin6_addr));
        event->requested_port = bpf_ntohs(addr.sin6_port);
    } else {
        return;
    }
    event->requested_family = family;
}

SEC("fexit/inet_stream_connect")
int BPF_PROG(on_connect_exit, struct socket *socket, struct sockaddr_unsized *addr,
             int length, int flags, int result)
{
    struct sock *sk = BPF_CORE_READ(socket, sk);

    if (!sk || BPF_CORE_READ(sk, sk_protocol) != LNFR_IPPROTO_TCP)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 netns = socket_netns(sk);

    if (!matches_filter(pid_tgid, netns))
        return 0;

    const __u64 *start = bpf_map_lookup_elem(&connect_started, &pid_tgid);
    __u64 started = start ? *start : 0;

    if (start)
        bpf_map_delete_elem(&connect_started, &pid_tgid);

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_event(sk, pid_tgid, netns, TCP_CONNECT, counts);

    if (event) {
        event->result = result;
        if (started && started <= event->monotonic_ns)
            event->connect_elapsed_ns = event->monotonic_ns - started;
        read_requested_peer(event, addr, length);
        submit_event(event, counts);
    }
    return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(on_accept, struct sock *listener, struct proto_accept_arg *arg,
             struct sock *accepted)
{
    if (!accepted || BPF_CORE_READ(accepted, sk_protocol) != LNFR_IPPROTO_TCP)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 netns = socket_netns(accepted);

    if (!matches_filter(pid_tgid, netns))
        return 0;

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_event(accepted, pid_tgid, netns, TCP_ACCEPT, counts);

    if (event)
        submit_event(event, counts);
    return 0;
}

struct tcp_minimum_header {
    __be16 source;
    __be16 dest;
    __u8 sequence_and_ack[8];
    __u8 data_offset;
    __u8 flags;
    __u8 window_checksum_urgent[6];
} __attribute__((packed));

static __always_inline int observe_tc(struct __sk_buff *skb, __u8 kind)
{
    /* Read network-relative headers only. Unsupported or short packets pass through. */
    __u32 offset;
    __u16 family;
    __u8 src[16] = {};
    __u8 dst[16] = {};
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr header;

        if (bpf_skb_load_bytes_relative(skb, 0, &header, sizeof(header), BPF_HDR_START_NET))
            return TCX_NEXT;
        offset = (__u32)header.ihl * 4;
        if (header.version != 4 || offset < sizeof(header) ||
            header.protocol != LNFR_IPPROTO_TCP ||
            (bpf_ntohs(header.frag_off) & 0x3fff) != 0 ||
            bpf_ntohs(header.tot_len) < offset + 20)
            return TCX_NEXT;
        family = LNFR_AF_INET;
        __builtin_memcpy(src, &header.saddr, sizeof(header.saddr));
        __builtin_memcpy(dst, &header.daddr, sizeof(header.daddr));
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr header;

        if (bpf_skb_load_bytes_relative(skb, 0, &header, sizeof(header), BPF_HDR_START_NET))
            return TCX_NEXT;
        if (header.version != 6 || header.nexthdr != LNFR_IPPROTO_TCP ||
            bpf_ntohs(header.payload_len) < 20)
            return TCX_NEXT;
        family = LNFR_AF_INET6;
        offset = sizeof(header);
        __builtin_memcpy(src, &header.saddr, sizeof(header.saddr));
        __builtin_memcpy(dst, &header.daddr, sizeof(header.daddr));
    } else {
        return TCX_NEXT;
    }

    struct tcp_minimum_header tcp;

    if (bpf_skb_load_bytes_relative(skb, offset, &tcp, sizeof(tcp), BPF_HDR_START_NET) ||
        tcp.data_offset >> 4 < 5)
        return TCX_NEXT;

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_record(family, tc_netns, kind, counts);

    if (event) {
        event->local_port = bpf_ntohs(tcp.source);
        event->remote_port = bpf_ntohs(tcp.dest);
        event->ifindex = skb->ifindex;
        event->skb_len = skb->len;
        event->tcp_flags = tcp.flags;
        __builtin_memcpy(event->local_addr, src, sizeof(src));
        __builtin_memcpy(event->remote_addr, dst, sizeof(dst));
        submit_event(event, counts);
    }
    return TCX_NEXT;
}

SEC("tcx/ingress")
int on_tc_ingress(struct __sk_buff *skb)
{
    return observe_tc(skb, TC_INGRESS_OBSERVED);
}

SEC("tcx/egress")
int on_tc_egress(struct __sk_buff *skb)
{
    return observe_tc(skb, TC_EGRESS_OBSERVED);
}

SEC("fentry/__br_forward")
int BPF_PROG(on_bridge_forward, const struct net_bridge_port *to,
             struct sk_buff *skb, bool local_orig)
{
    if (!to || !skb)
        return 0;

    struct net_device *bridge = BPF_CORE_READ(to, br, dev);

    if (!bridge || BPF_CORE_READ(bridge, ifindex) != bridge_ifindex ||
        BPF_CORE_READ(bridge, nd_net.net, ns.inum) != bridge_netns)
        return 0;

    int egress_ifindex = BPF_CORE_READ(to, dev, ifindex);
    int ingress_ifindex = local_orig ? 0 : BPF_CORE_READ(skb, dev, ifindex);
    __u16 mac_header = BPF_CORE_READ(skb, mac_header);
    unsigned int tail = BPF_CORE_READ(skb, tail);
    unsigned char *head = BPF_CORE_READ(skb, head);

    if (egress_ifindex <= 0 || (!local_orig && ingress_ifindex <= 0) ||
        !head || mac_header == (__u16)-1 || tail < mac_header ||
        tail - mac_header < ETH_HLEN)
        return 0;

    struct ethhdr ethernet;

    if (bpf_probe_read_kernel(&ethernet, sizeof(ethernet), head + mac_header))
        return 0;

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_record(
        bpf_ntohs(ethernet.h_proto), bridge_netns, BRIDGE_FORWARD_OBSERVED, counts);

    if (event) {
        event->bridge_ifindex = bridge_ifindex;
        event->ingress_ifindex = ingress_ifindex;
        event->ifindex = egress_ifindex;
        event->skb_len = BPF_CORE_READ(skb, len);
        event->local_origin = local_orig;
        __builtin_memcpy(event->local_addr, ethernet.h_source, ETH_ALEN);
        __builtin_memcpy(event->remote_addr, ethernet.h_dest, ETH_ALEN);
        submit_event(event, counts);
    }
    return 0;
}

static __always_inline int observe_route(struct sk_buff *skb, __u16 family)
{
    if (!skb)
        return 0;

    struct net_device *ingress = BPF_CORE_READ(skb, dev);

    if (!ingress || BPF_CORE_READ(ingress, nd_net.net, ns.inum) != route_netns)
        return 0;

    unsigned long refdst = BPF_CORE_READ(skb, _skb_refdst);
    struct dst_entry *route = (void *)(refdst & ~LNFR_SKB_DST_NOREF);

    if (!route)
        return 0;

    int ingress_ifindex = BPF_CORE_READ(ingress, ifindex);
    int egress_ifindex = BPF_CORE_READ(route, dev, ifindex);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    unsigned int tail = BPF_CORE_READ(skb, tail);
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u8 src[16] = {};
    __u8 dst[16] = {};
    __u8 hop_limit;
    __u8 next_header;

    if (ingress_ifindex <= 0 || egress_ifindex <= 0 || !head ||
        network_header == (__u16)-1 || tail < network_header)
        return 0;

    if (family == LNFR_AF_INET) {
        struct iphdr header;

        if (tail - network_header < sizeof(header) ||
            bpf_probe_read_kernel(&header, sizeof(header), head + network_header) ||
            header.version != 4 || header.ihl < 5)
            return 0;
        __builtin_memcpy(src, &header.saddr, sizeof(header.saddr));
        __builtin_memcpy(dst, &header.daddr, sizeof(header.daddr));
        hop_limit = header.ttl;
        next_header = header.protocol;
    } else {
        struct ipv6hdr header;

        if (tail - network_header < sizeof(header) ||
            bpf_probe_read_kernel(&header, sizeof(header), head + network_header) ||
            header.version != 6)
            return 0;
        __builtin_memcpy(src, &header.saddr, sizeof(header.saddr));
        __builtin_memcpy(dst, &header.daddr, sizeof(header.daddr));
        hop_limit = header.hop_limit;
        next_header = header.nexthdr;
    }

    struct capture_stats *counts = get_stats();
    struct tcp_event_v2 *event = reserve_record(
        family, route_netns, ROUTE_FORWARD_OBSERVED, counts);

    if (event) {
        event->ingress_ifindex = ingress_ifindex;
        event->ifindex = egress_ifindex;
        event->skb_len = BPF_CORE_READ(skb, len);
        event->hop_limit = hop_limit;
        event->ip_next_header = next_header;
        __builtin_memcpy(event->local_addr, src, sizeof(src));
        __builtin_memcpy(event->remote_addr, dst, sizeof(dst));
        submit_event(event, counts);
    }
    return 0;
}

SEC("fentry/ip_forward")
int BPF_PROG(on_ipv4_forward, struct sk_buff *skb)
{
    return observe_route(skb, LNFR_AF_INET);
}

SEC("fentry/ip6_forward")
int BPF_PROG(on_ipv6_forward, struct sk_buff *skb)
{
    return observe_route(skb, LNFR_AF_INET6);
}

char LICENSE[] SEC("license") = "GPL";

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Yutaro Hayakawa */

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/seg6.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6_local.h>
#include <linux/bpf.h>
#include <linux/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Keep below definitions sync with Zebra side
 */
struct seg6local_key {
  struct bpf_lpm_trie_key base;
  struct in6_addr prefix;
  __u8 _pad[12];
} __attribute__((packed));

struct seg6local_val {
  __u32 action;
  union {
    __u32 vrftable;
  } attr;
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct seg6local_key);
  __type(value, struct seg6local_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} zebra_seg6local_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} vrftable2ifindex SEC(".maps");

static __inline int
action_end_dt4(struct __sk_buff *skb, __u32 ofs, struct ipv6hdr *ipv6,
    struct ipv6_sr_hdr *sr, __u32 vrftable)
{
  int ret, room, *ifindex;
  __u16 new_proto = bpf_htons(ETH_P_IP);
  struct bpf_fib_lookup fib_params = {0};

  /* Segments Left should be 0 for End.DT4. Just silently drop the packet
   * instead of sending ICMP.
   */
  if (sr->segments_left != 0) {
    return TC_ACT_SHOT;
  }

  /* Currently we only support the case that IPv4 header comes right after
   * the SRH.
   */
  if (sr->nexthdr != IPPROTO_IPIP) {
    return TC_ACT_SHOT;
  }

  if (bpf_skb_change_proto(skb, new_proto, 0) < 0) {
    return TC_ACT_SHOT;
  }

  if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
        &new_proto, sizeof(new_proto), 0) < 0) {
    return TC_ACT_SHOT;
  }

  room = -((int)sizeof(struct iphdr) + (int)sizeof(*sr) + (int)sizeof(sr->segments[0]));
  if (bpf_skb_adjust_room(skb, room, BPF_ADJ_ROOM_MAC,
        BPF_F_ADJ_ROOM_NO_CSUM_RESET)) {
    return TC_ACT_SHOT;
  }

  ifindex = bpf_map_lookup_elem(&vrftable2ifindex, &vrftable);
  if (ifindex == NULL) {
    return TC_ACT_SHOT;
  }

  // Redirect packet to VRF device. So that it will be routed with the VRF's table.
  return bpf_redirect(*ifindex, 0);
}

static __inline int
handle_seg6(struct __sk_buff *skb, __u32 ofs, struct ipv6hdr *ipv6, struct seg6local_val *v)
{
  int ret;
  void *data = skb->data;
  void *data_end = skb->data_end;
  struct ipv6_rt_hdr *rt = data + ofs;
  struct ipv6_sr_hdr *sr = data + ofs;

  if (data + ofs + sizeof(*rt) > data_end) {
    return TC_ACT_OK;
  }

  /*
   * Currently, only support the simple case that SR header comes right after
   * the IPv6 header.
   */
  if (rt->type != IPV6_SRCRT_TYPE_4) {
    return TC_ACT_OK;
  }

  if (data + ofs + sizeof(*sr) > data_end) {
    return TC_ACT_OK;
  }

  ofs += sizeof(*sr) + sr->hdrlen * 8;

  switch (v->action) {
    case SEG6_LOCAL_ACTION_END_DT4:
      ret = action_end_dt4(skb, ofs, ipv6, sr, v->attr.vrftable);
      break;
    default:
      ret = TC_ACT_OK;
      break;
  }

  return ret;
}

static __inline int
handle_ipv6(struct __sk_buff *skb, __u32 ofs)
{
  int ret;
  void *data = skb->data;
  void *data_end = skb->data_end;
  struct ipv6hdr *ipv6 = data + ofs;
  struct seg6local_key k = {0};
  struct seg6local_val *v;

  if (data + ofs + sizeof(*ipv6) > data_end) {
    return TC_ACT_OK;
  }

  ofs += sizeof(*ipv6);

  k.base.prefixlen = 8 * (sizeof(k) - sizeof(k.base.prefixlen));
  k.prefix = ipv6->daddr;

  /* Do we have a seg6local entry? */
  v = bpf_map_lookup_elem(&zebra_seg6local_map, &k);
  if (v == NULL) {
    return TC_ACT_OK;
  }

  // Found, process it.
  return handle_seg6(skb, ofs, ipv6, v);
}

static __inline int
handle_eth(struct __sk_buff *skb)
{
  int ret;
  void *data = skb->data;
  void *data_end = skb->data_end;
  struct ethhdr *eth = data;

  if (data + sizeof(*eth) > data_end) {
    return TC_ACT_OK;
  }

  __u16 proto = bpf_ntohs(skb->protocol);

  switch (proto) {
    case ETH_P_IPV6:
      ret = handle_ipv6(skb, sizeof(*eth));
      break;
    default:
      ret = TC_ACT_OK;
      break;
  }

  return ret;
}

SEC("tc") int
ingress_main(struct __sk_buff *skb)
{
  return handle_eth(skb);
}

char __license[] SEC("license") = "Dual BSD/GPL";

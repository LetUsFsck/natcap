/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Thu, 30 Aug 2018 11:25:35 +0800
 *
 * This file is part of the natcap.
 *
 * natcap is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * natcap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with natcap; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "natcap_common.h"
#include "natcap_peer.h"

/*XXX: 240.229.229.242
 * code: p    e    e    r
 *  hex: 0x70 0x65 0x65 0x72
 * +128: 0xF0 0xE5 0xE5 0xF2
 */
__be32 peer_icmp_dst = htonl((240<<24)|(229<<16)|(229<<8)|(242<<0));

//193.112.28.48
__be32 peer_server_ip = htonl((193<<24)|(112<<16)|(28<<8)|(48<<0));
__be16 peer_server_port = 0;
__be16 peer_client_port = 0;

static inline void peer_init_port(int x)
{
	if (peer_server_port == 0 || x != 0) {
		peer_server_port = htons(1024 + prandom_u32() % (65535 - 1024 + 1));
	}
	if (peer_client_port == 0 || x != 0) {
		peer_client_port = htons(1024 + prandom_u32() % (65535 - 1024 + 1));
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_peer_post_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_post_out_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct sk_buff *skb2;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;
	struct natcap_TCPOPT *tcpopt;
	int offset, header_len;
	int size;

	//if (disabled)
	//	return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_ICMP) {
		return NF_ACCEPT;
	}
	if (iph->daddr != peer_icmp_dst) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	NATCAP_INFO("(PPO)" DEBUG_ICMP_FMT ": ping out\n", DEBUG_ICMP_ARG(iph,l4));

	size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
	offset = iph->ihl * 4 + sizeof(struct tcphdr) + size - skb->len;
	header_len = offset < 0 ? 0 : offset;
	skb2 = skb_copy_expand(skb, skb_headroom(skb), header_len, GFP_ATOMIC);
	if (!skb2) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return NF_DROP;
	}
	if (offset <= 0) {
		if (pskb_trim(skb2, skb2->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, skb2->len, offset);
			consume_skb(skb2);
			return NF_DROP;
		}
	} else {
		skb2->len += offset;
		skb2->tail += offset;
	}

	skb_nfct_reset(skb2);
	iph = ip_hdr(skb2);
	l4 = (void *)iph + iph->ihl * 4;
	tcpopt = (struct natcap_TCPOPT *)(l4 + sizeof(struct tcphdr));

	skb2->protocol = htons(ETH_P_IP);
	iph->protocol = IPPROTO_TCP;
	iph->daddr = peer_server_ip;
	iph->tot_len = htons(skb2->len);
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	tcpopt->header.opcode = TCPOPT_PEER;
	tcpopt->header.opsize = size;
	tcpopt->header.encryption = 0;

	peer_init_port(0);

	TCPH(l4)->source = peer_client_port;
	TCPH(l4)->dest = peer_server_port;
	TCPH(l4)->seq = ntohl(jiffies);
	TCPH(l4)->ack_seq = 0;
	TCPH(l4)->res1 = 0;
	TCPH(l4)->doff = (sizeof(struct tcphdr) + size) / 4;
	TCPH(l4)->syn = 1;
	TCPH(l4)->rst = 0;
	TCPH(l4)->psh = 0;
	TCPH(l4)->ack = 0;
	TCPH(l4)->fin = 0;
	TCPH(l4)->urg = 0;
	TCPH(l4)->ece = 0;
	TCPH(l4)->cwr = 0;
	TCPH(l4)->window = 65535;
	TCPH(l4)->check = 0;
	TCPH(l4)->urg_ptr = 0;

	skb_rcsum_tcpudp(skb2);

	iph = ip_hdr(skb2);
	l4 = (void *)iph + iph->ihl * 4;

	ret = nf_conntrack_in(net, pf, NF_INET_PRE_ROUTING, skb2);
	if (ret != NF_ACCEPT) {
		if (ret != NF_STOLEN) {
			consume_skb(skb2);
		}
		goto out;
	}

	ct = nf_ct_get(skb2, &ctinfo);
	if (NULL == ct) {
		consume_skb(skb2);
		goto out;
	}

	if (!(IPS_NATCAP_PEER & ct->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &ct->status)) {
		NATCAP_INFO("(PPO)" DEBUG_TCP_FMT ": ping out\n", DEBUG_TCP_ARG(iph,l4));
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb2);
	if (ret != NF_ACCEPT) {
		if (ret != NF_STOLEN) {
			consume_skb(skb2);
		}
		goto out;
	}

	NF_OKFN(skb2);

out:
	consume_skb(skb);
	return NF_STOLEN;
}

static struct nf_hook_ops peer_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 5,
	},
};

int natcap_peer_init(void)
{
	int ret = 0;

	need_conntrack();

	ret = nf_register_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));
	return ret;
}

void natcap_peer_exit(void)
{
	nf_unregister_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));
}

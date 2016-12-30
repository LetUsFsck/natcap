/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:04 +0800
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
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include "natcap_common.h"
#include "natcap_client.h"

unsigned long long flow_total_tx_bytes = 0;
unsigned long long flow_total_rx_bytes = 0;

unsigned int server_persist_timeout = 0;
module_param(server_persist_timeout, int, 0);
MODULE_PARM_DESC(server_persist_timeout, "Use diffrent server after timeout");

u32 default_u_hash = 0;
unsigned char default_mac_addr[ETH_ALEN];
static void default_mac_addr_init(void)
{
	struct net_device *dev;
	dev = first_net_device(&init_net);
	while (dev) {
		if (dev->type == ARPHRD_ETHER) {
			memcpy(default_mac_addr, dev->dev_addr, ETH_ALEN);
			break;
		}
		dev = next_net_device(dev);
	}

	dev = first_net_device(&init_net);
	while (dev) {
		if (strcmp("eth0", dev->name) == 0) {
			memcpy(default_mac_addr, dev->dev_addr, ETH_ALEN);
			break;
		}
		dev = next_net_device(dev);
	}
}

#define MAX_NATCAP_SERVER 256
struct natcap_server_info {
	unsigned int active_index;
	unsigned int server_count[2];
	struct tuple server[2][MAX_NATCAP_SERVER];
};

static struct natcap_server_info natcap_server_info;

void natcap_server_info_cleanup(void)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;

	nsi->server_count[m] = 0;
	nsi->server_count[n] = 0;
	nsi->active_index = n;
}

int natcap_server_info_add(const struct tuple *dst)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;
	unsigned int i, j;

	if (nsi->server_count[m] == MAX_NATCAP_SERVER)
		return -ENOSPC;

	for (i = 0; i < nsi->server_count[m]; i++) {
		if (tuple_eq(&nsi->server[m][i], dst)) {
			return -EEXIST;
		}
	}

	/* all dst(s) are stored from MAX to MIN */
	j = 0;
	for (i = 0; i < nsi->server_count[m] && tuple_lt(dst, &nsi->server[m][i]); i++) {
		tuple_copy(&nsi->server[n][j++], &nsi->server[m][i]);
	}
	tuple_copy(&nsi->server[n][j++], dst);
	for (; i < nsi->server_count[m]; i++) {
		tuple_copy(&nsi->server[n][j++], &nsi->server[m][i]);
	}

	nsi->server_count[n] = j;
	nsi->active_index = n;

	return 0;
}

int natcap_server_info_delete(const struct tuple *dst)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;
	unsigned int i, j;

	j = 0;
	for (i = 0; i < nsi->server_count[m]; i++) {
		if (tuple_eq(&nsi->server[m][i], dst)) {
			continue;
		}
		tuple_copy(&nsi->server[n][j++], &nsi->server[m][i]);
	}
	if (j == i)
		return -ENOENT;

	nsi->server_count[n] = j;

	nsi->active_index = n;

	return 0;
}

void *natcap_server_info_get(loff_t idx)
{
	if (idx < natcap_server_info.server_count[natcap_server_info.active_index])
		return &natcap_server_info.server[natcap_server_info.active_index][idx];
	return NULL;
}

void natcap_server_info_select(__be32 ip, __be16 port, struct tuple *dst)
{
	static unsigned int server_index = 0;
	static unsigned long server_jiffies = 0;
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int count = nsi->server_count[m];
	unsigned int hash;

	dst->ip = 0;
	dst->port = 0;
	dst->encryption = 0;

	if (count == 0)
		return;

	if (time_after(jiffies, server_jiffies + server_persist_timeout * HZ)) {
		server_jiffies = jiffies;
		server_index++;
	}

	//hash = server_index ^ ntohl(ip);
	hash = server_index;
	hash = hash % count;

	tuple_copy(dst, &nsi->server[m][hash]);
	if (dst->port == __constant_htons(0)) {
		dst->port = port;
	} else if (dst->port == __constant_htons(65535)) {
		dst->port = ((jiffies^ip) & 0xFFFF);
	}

	if (port == __constant_htons(443) || port == __constant_htons(22)) {
		dst->encryption = 0;
	}
}

static inline int is_natcap_server(__be32 ip)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int i;

	for (i = 0; i < nsi->server_count[m]; i++) {
		if (nsi->server[m][i].ip == ip)
			return 1;
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_dnat_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_dnat_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_dnat_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_dnat_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct tuple server;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		goto bypass_out;
	}
	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		goto natcaped_out;
	}
	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (TCPH(l4)->doff * 4 < sizeof(struct tcphdr)) {
			return NF_DROP;
		}
	} else {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
	}

	if (ip_set_test_dst_ip(in, out, skb, "gfwlist") > 0) {
		natcap_server_info_select(iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
		if (server.ip == 0) {
			if (iph->protocol == IPPROTO_TCP) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": no server found\n", DEBUG_TCP_ARG(iph,l4));
			} else {
				NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": no server found\n", DEBUG_UDP_ARG(iph,l4));
			}
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			goto bypass_out;
		}
		if (server.encryption) {
			set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		}
		if (iph->protocol == IPPROTO_TCP) {
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, before encode, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		} else {
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": new connection, before encode, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
		}
	} else {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		goto bypass_out;
	}

	if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time out */
		if (iph->protocol == IPPROTO_TCP) {
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, after encode, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		} else {
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": new connection, after encode, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
		}
		if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
			if (iph->protocol == IPPROTO_TCP) {
				NATCAP_ERROR("(CD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			} else {
				NATCAP_ERROR("(CD)" DEBUG_UDP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
			}
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
		if (encode_mode == UDP_ENCODE) {
			set_bit(IPS_NATCAP_UDPENC_BIT, &ct->status);
		}
	}

	if (iph->protocol == IPPROTO_TCP) {
		NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));
	} else {
		NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": after encode\n", DEBUG_UDP_ARG(iph,l4));
	}

natcaped_out:
	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (TCPH(l4)->syn && !TCPH(l4)->ack &&
				(TCPH(l4)->dest == __constant_htons(80) || TCPH(l4)->dest == __constant_htons(443))) {
			if (!test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn1\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			if (!test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn2\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			if (!test_and_set_bit(IPS_NATCAP_SYN3_BIT, &ct->status)) {
				NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": natcaped syn3 del target from gfwlist\n", DEBUG_TCP_ARG(iph,l4));
				ip_set_del_dst_ip(in, out, skb, "gfwlist");
			}
		}
	}
	return NF_ACCEPT;

bypass_out:
	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
			if (TCPH(l4)->syn && !TCPH(l4)->ack &&
					(TCPH(l4)->dest == __constant_htons(80) || TCPH(l4)->dest == __constant_htons(443))) {
				if (!test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
					NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": bypass syn1\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
				if (!test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
					NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": bypass syn2\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
				if (!test_and_set_bit(IPS_NATCAP_SYN3_BIT, &ct->status)) {
					if (!is_natcap_server(iph->daddr) && ip_set_test_dst_ip(in, out, skb, "cniplist") <= 0) {
						NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": bypass syn3 add target to gfwlist\n", DEBUG_TCP_ARG(iph,l4));
						ip_set_add_dst_ip(in, out, skb, "gfwlist");
					}
				}
			}
		} else {
			if (TCPH(l4)->rst && TCPH(l4)->source == __constant_htons(80)
					&& ip_set_test_src_ip(in, out, skb, "cniplist") <= 0) {
				NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": bypass get reset add target to gfwlist\n", DEBUG_TCP_ARG(iph,l4));
				ip_set_add_src_ip(in, out, skb, "gfwlist");
			}
		}
	}
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_pre_ct_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_client_pre_ct_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_TCPOPT tcpopt;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		return NF_ACCEPT;
	}

	flow_total_rx_bytes += skb->len;

	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (TCPH(l4)->doff * 4 < sizeof(struct tcphdr)) {
			return NF_DROP;
		}
		if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4)->doff * 4)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": before decode\n", DEBUG_TCP_ARG(iph,l4));

		tcpopt.header.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		ret = natcap_tcp_decode(skb, &tcpopt);
		if (ret != 0) {
			NATCAP_ERROR("(CPCI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
			return NF_DROP;
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,l4));
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (*((unsigned int *)((void *)UDPH(l4) + sizeof(struct udphdr))) == __constant_htonl(0xFFFE009A)) {
			if (!test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
				NATCAP_INFO("(CPCI)" DEBUG_UDP_FMT ": got CFM pkt\n", DEBUG_UDP_ARG(iph,l4));
			}
			return NF_DROP;
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_UDP_FMT ": after decode\n", DEBUG_UDP_ARG(iph,l4));
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_pre_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_client_pre_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	struct iphdr *iph;
	void *l4;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (skb_is_gso(skb)) {
		NATCAP_ERROR("(CPI)" DEBUG_UDP_FMT ": skb_is_gso\n", DEBUG_UDP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	if (*((unsigned int *)((void *)UDPH(l4) + 8)) == __constant_htonl(0xFFFF0099)) {
		int offlen;

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			skb->csum = 0;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}

		offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4 - 8;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(l4) + 4, (void *)UDPH(l4) + 4 + 8, offlen);
		iph->tot_len = htons(ntohs(iph->tot_len) - 8);
		skb->len -= 8;
		skb->tail -= 8;
		iph->protocol = IPPROTO_TCP;
		skb_rcsum_tcpudp(skb);
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_post_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_client_post_out_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	unsigned long status = NATCAP_CLIENT_MODE;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_TCPOPT tcpopt;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		/* for REPLY post out */
		if (iph->protocol == IPPROTO_TCP) {
			if (test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) {
				natcap_adjust_tcp_mss(TCPH(l4), -8);
			}
		}
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP) {
		if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
			status |= NATCAP_NEED_ENC;
		}

		ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt);
		if (ret == 0) {
			ret = natcap_tcp_encode(skb, &tcpopt);
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}
		if (ret != 0) {
			NATCAP_ERROR("(CO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}

		NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));

		if (!test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) {
			flow_total_tx_bytes += skb->len;
			return NF_ACCEPT;
		}

		/* XXX I just confirm it first  */
		ret = nf_conntrack_confirm(skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}

		if (skb_is_gso(skb)) {
			struct sk_buff *segs;

			segs = skb_gso_segment(skb, 0);
			if (IS_ERR(segs)) {
				return NF_DROP;
			}

			consume_skb(skb);
			skb = segs;
		}

		do {
			int offlen;
			struct sk_buff *nskb = skb->next;

			if (skb->end - skb->tail < 8 && pskb_expand_head(skb, 0, 8, GFP_ATOMIC)) {
				consume_skb(skb);
				skb = nskb;
				NATCAP_ERROR("pskb_expand_head failed\n");
				continue;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4;
			BUG_ON(offlen < 0);
			memmove((void *)UDPH(l4) + 4 + 8, (void *)UDPH(l4) + 4, offlen);
			iph->tot_len = htons(ntohs(iph->tot_len) + 8);
			UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
			skb->len += 8;
			skb->tail += 8;
			*((unsigned int *)((void *)UDPH(l4) + 8)) = __constant_htonl(0xFFFF0099);
			iph->protocol = IPPROTO_UDP;
			skb_rcsum_tcpudp(skb);

			NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT "\n", DEBUG_UDP_ARG(iph,l4));

			flow_total_tx_bytes += skb->len;

			skb->next = NULL;
			NF_OKFN(skb);

			skb = nskb;
		} while (skb);

		return NF_STOLEN;
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!test_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
			if (skb->len > 1280) {
				struct sk_buff *nskb;
				int offset, header_len;

				offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 12 - skb->len;
				header_len = offset < 0 ? 0 : offset;
				nskb = skb_copy_expand(skb, skb_headroom(skb), header_len, GFP_ATOMIC);
				if (!nskb) {
					NATCAP_ERROR("alloc_skb fail\n");
					return NF_ACCEPT;
				}

				nskb->len += offset;

				iph = ip_hdr(nskb);
				l4 = (void *)iph + iph->ihl * 4;
				iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 12);
				UDPH(l4)->len = ntohs(sizeof(struct udphdr) + 12);
				*((unsigned int *)(l4 + sizeof(struct udphdr))) = __constant_htonl(0xFFFE0099);
				*((unsigned int *)(l4 + sizeof(struct udphdr) + 4)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 8)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 10)) = __constant_htons(0x1);
				skb_rcsum_tcpudp(nskb);

				NF_OKFN(nskb);
			} else {
				int offlen;

				if (skb->end - skb->tail < 12 && pskb_expand_head(skb, 0, 12, GFP_ATOMIC)) {
					NATCAP_ERROR("pskb_expand_head failed\n");
					return NF_ACCEPT;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr);
				BUG_ON(offlen < 0);
				memmove((void *)UDPH(l4) + sizeof(struct udphdr) + 12, (void *)UDPH(l4) + sizeof(struct udphdr), offlen);
				iph->tot_len = htons(ntohs(iph->tot_len) + 12);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				skb->len += 12;
				skb->tail += 12;
				*((unsigned int *)(l4 + sizeof(struct udphdr))) = __constant_htonl(0xFFFE0099);
				*((unsigned int *)(l4 + sizeof(struct udphdr) + 4)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 8)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 10)) = __constant_htons(0x2);
				skb_rcsum_tcpudp(skb);
			}
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops client_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 35,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_NAT_DST - 35,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

int natcap_client_init(void)
{
	int ret = 0;

	need_conntrack();

	natcap_server_info_cleanup();
	default_mac_addr_init();
	ret = nf_register_hooks(client_hooks, ARRAY_SIZE(client_hooks));
	return ret;
}

void natcap_client_exit(void)
{
	nf_unregister_hooks(client_hooks, ARRAY_SIZE(client_hooks));
}

/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/export.h>
#include <linux/rculist.h>
#include "br_private.h"

/* Hook for brouter */
br_should_route_hook_t __rcu *br_should_route_hook __read_mostly;
EXPORT_SYMBOL(br_should_route_hook);

//从网桥处理流程进入本地协议栈
static int br_pass_frame_up(struct sk_buff *skb)
{
	struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(brdev);//获取网桥信息
	struct br_cpu_netstats *brstats = this_cpu_ptr(br->stats);

	u64_stats_update_begin(&brstats->syncp);
	brstats->rx_packets++;
	brstats->rx_bytes += skb->len;
	u64_stats_update_end(&brstats->syncp);

	/* Bridge is just like any other port.  Make sure the
	 * packet is allowed except in promisc modue when someone
	 * may be running packet capture.
	 */
	if (!(brdev->flags & IFF_PROMISC) &&
	    !br_allowed_egress(br, br_get_vlan_info(br), skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	skb = br_handle_vlan(br, br_get_vlan_info(br), skb);//br_handle_vlan的作用是什么？
	if (!skb)
		return NET_RX_DROP;

	indev = skb->dev;
	skb->dev = brdev;/*将skb->dev更新为brdev，即网桥设备，而不是实际物理口，这样子，重新走netif_receive_skb_sk时rx_handle就不会有值了*/
//最后会再次调用netif_receive_skb重新接受数据包,但是这时skb->dev是网桥，并且网桥设备的rx_handler指针肯定为空，那么就不会再次进入网桥的处理，而是直接交付上层了
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
		       netif_receive_skb);
/*前面已经提到，在netif_receive_skb函数中，调用了handle_bridge函数，并且触发了  网桥
的处理流程，现在发往网桥虚拟设备的数据
包又回到了netif_receive_skb,那么网桥的处理过程会不会又被
调用到呢？     在 linux/net/bridge/br_if.c里面可以看
到br_add_if函数，实际上的操作是将某一网口加入网桥组，这个函数调用了new_nbp(br, dev); 用以填充net_bridge以及dev结构的
重要成员，里面将dev->br_port设定为一个新建的net_bridge_port结构，而上面的br_pass_frame_up函数将skb->dev赋成了br->dev,实际上skb->dev变成了网桥建立的虚拟设备，这个设备是网
桥本身而不是桥组的某一端口，系统没有为其调用br_add_if，所以这个net_device结构的br_port指针没有进行赋值。*/
}

/* note: already called with rcu_read_lock */
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_mdb_entry *mdst;
	struct sk_buff *skb2;
	u16 vid = 0;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

	if (!br_allowed_ingress(p->br, nbp_get_vlan_info(p), skb, &vid))//是否允许从桥上转发
		goto out;

	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;
	br_fdb_update(br, p, eth_hdr(skb)->h_source, vid);//更新转发数据库

	if (!is_broadcast_ether_addr(dest) && is_multicast_ether_addr(dest) &&
	    br_multicast_rcv(br, p, skb))
		goto drop;

	if (p->state == BR_STATE_LEARNING)
		goto drop;

	BR_INPUT_SKB_CB(skb)->brdev = br->dev;

	/* The packet skb2 goes to the local host (NULL to skip). */
	skb2 = NULL;

	if (br->dev->flags & IFF_PROMISC)//网桥设备是否处于混杂状态？
		skb2 = skb;//如果是则建立副本，为发往本地做个备份

	dst = NULL;

	if (is_broadcast_ether_addr(dest))//是广播地址？
		skb2 = skb;//仅仅设置副本，进行广播转发和发往本地
	else if (is_multicast_ether_addr(dest)) {
	//先查多播地址转发表，如果存在，设置副本，进行多播转发，原始数据包指向NULL,如果已经传送至本地，
	//则会释放副本，不进行本地转发，否则重新转发到本地
		mdst = br_mdb_get(br, skb, vid);
		if (mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) {
			if ((mdst && mdst->mglist) ||
			    br_multicast_is_router(br))
				skb2 = skb;
			br_multicast_forward(mdst, skb, skb2);
			skb = NULL;
			if (!skb2)
				goto out;
		} else
			skb2 = skb;

		br->dev->stats.multicast++;
	} else if ((dst = __br_fdb_get(br, dest, vid)) &&
			dst->is_local) {
		skb2 = skb;
		/* Do not forward the packet since it's local. */
		skb = NULL;
	}
	/*1. fdb 表中存在表项且是本地端口或者组播处理完成，设置 skb2 = skb, skb = null, unicast = false, dst != null
	  2. 广播或者组播未处理完成 skb2 = skb, skb != null, unicast = false, dst = null
	  3. fdb表中不存在表项（未知单播），skb2 = null, skb != null, unicast = true， dst = null
	  4. fdb表中找到表项但不是本地端口， skb2 = null, skb != null, unicast = true, dst != null
	 */

	if (skb) {
		if (dst) {
			dst->used = jiffies;
			br_forward(dst->dst, skb, skb2);//转发数据包
		} else
			br_flood_forward(br, skb, skb2);//广播数据包
	}

	if (skb2)
		return br_pass_frame_up(skb2);//发送本地

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}

/* note: already called with rcu_read_lock */
static int br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	u16 vid = 0;

	br_vlan_get_tag(skb, &vid);
	br_fdb_update(p->br, p, eth_hdr(skb)->h_source, vid);//更新网桥接口地址表
	return 0;	 /* process further */
}

/*
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock
 */
rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;// /*获取目的MAC地址*/
	br_should_route_hook_t *rhook;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;

	p = br_port_get_rcu(skb->dev);

	if (unlikely(is_link_local_ether_addr(dest))) {
		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		switch (dest[5]) {//目的mac地址是否是01 80 c2 00 0x类型
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP)
				goto forward;
			break;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		default:
			/* Allow selective forwarding for most other protocols */
			if (p->br->group_fwd_mask & (1u << dest[5]))
				goto forward;
		}

		/* Deliver packet to local host only */
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,////处理NF_BR_LOCAL_IN的ebtables相关的规则。
			    NULL, br_handle_local_finish)) {//调用函数  br_handle_frame_finish继续进行数据处理
			return RX_HANDLER_CONSUMED; /* consumed by filter */
		} else {
			*pskb = skb;
			return RX_HANDLER_PASS;	/* continue processing */
		}
	}

forward:
	switch (p->state) {
	case BR_STATE_FORWARDING:
		rhook = rcu_dereference(br_should_route_hook);
		if (rhook) {
			if ((*rhook)(skb)) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			dest = eth_hdr(skb)->h_dest;
		}
		/* fall through */
	case BR_STATE_LEARNING:
		if (ether_addr_equal(p->br->dev->dev_addr, dest))
			////如果数据包的目的地址和网桥的虚拟设备地址相同，则将数据包类型设为PACKET_HOST，也就是发往本地的数据
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(NFPROTO_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,//处理NF_BR_PRE_ROUTING的ebtables相关的规则。
			br_handle_frame_finish);//当通过NF_BR_PRE_ROUTING相关的ebtables规则后，则会调用函数  br_handle_frame_finish继续进行数据处理
		break;
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDLER_CONSUMED;
}

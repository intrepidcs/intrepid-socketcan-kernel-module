/*
 * intrepid.c - Netdevice driver for Intrepid CAN/Ethernet devices
 *
 * Copyright (c) 2016-2025 Intrepid Control Systems, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see http://www.gnu.org/licenses/gpl.html
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/rtnetlink.h>
#include <linux/fs.h>
#include <linux/if_arp.h>
#include <linux/vmalloc.h>
#include <linux/can.h>
#include <linux/can/skb.h>
#include <linux/can/dev.h>
#include <linux/can/error.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/version.h>
#include <linux/etherdevice.h>

#include "neomessage.h"

#define str_first(x) #x
#define str(x) str_first(x)

#define KO_DESC "Netdevice driver for Intrepid CAN/Ethernet devices"
#define KO_MAJOR 3
#define KO_MINOR 1
#define KO_PATCH 1
#define KO_VERSION str(KO_MAJOR) "." str(KO_MINOR) "." str(KO_PATCH)
#define KO_VERSION_INT (KO_MAJOR << 16) | (KO_MINOR << 8) | KO_PATCH

#define VER_MAJ_FROM_INT(VERINT) ((VERINT >> 16) & 0xFF)
#define VER_MIN_FROM_INT(VERINT) ((VERINT >> 8) & 0xFF)
#define VER_PATCH_FROM_INT(VERINT) (VERINT & 0xFF)

MODULE_DESCRIPTION(KO_DESC);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Paul Hollinsky <phollinsky@intrepidcs.com>");
MODULE_AUTHOR("Jeffrey Quesnelle <jeffq@intrepidcs.com>");
MODULE_AUTHOR("Kyle Schwarz <kschwarz@intrepidcs.com>");
MODULE_AUTHOR("Thomas Stoddard <tstoddard@intrepidcs.com>");
MODULE_VERSION(KO_VERSION);

#define INTREPID_DEVICE_NAME            "intrepid_netdevice"
#define INTREPID_CLASS_NAME             "intrepid"
#define MAX_NET_DEVICES                 64
#define SHARED_MEM_SIZE                 0x400000

#define SIOCSADDCANIF			0x3001
#define SIOCSADDETHIF			0x3002
#define SIOCSREMOVECANIF		0x3003
#define SIOCSREMOVEETHIF		0x3004
#define SIOCGSHAREDMEMSIZE		0x3005
#define SIOCSMSGSWRITTEN		0x3006
#define SIOCGMAXIFACES			0x3007
#define SIOCGVERSION			0x3008
#define SIOCGCLIENTVEROK		0x3009
#define SIOCSBAUDRATE			0x300A

/* This is true until we have Ethernet support
 * It is used to stop the netif queues before we have to return NETDEV_TX_BUSY
 */

#define KERNEL_CHECKS_MTU_RANGE         (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
#define KERNEL_FAULT_TAKES_VMA          (LINUX_VERSION_CODE <  KERNEL_VERSION(4,11,0))
#define KERNEL_SUPPORTS_ALIASES         (LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
#define KERNEL_DEFINES_VM_FAULT_T       (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define KERNEL_CAN_ECHO_TRACKS_LEN      (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))

#if KERNEL_DEFINES_VM_FAULT_T == 0
typedef int vm_fault_t;
#endif

struct intrepid_pending_tx_info {
	int tx_box_index;
	int count;
	size_t bytes;
};

struct intrepid_netdevice {
	struct can_priv         can;
	struct net_device       *dev;
	spinlock_t              lock;
	int                     is_stopped;
	unsigned char           *from_user;
	uint8_t                 tx_idx;
	int			bitrate_changed;
};

static int                      is_open;
static int                      major_number;
static int                      client_version;
static unsigned char            *shared_mem;
static struct class             *intrepid_dev_class;
static struct device            *intrepid_dev;
static struct net_device        **net_devices;
static struct mutex             ioctl_mutex;

static wait_queue_head_t        tx_wait;
static unsigned char            *tx_boxes[2];
static int                      current_tx_box;
static int                      tx_box_count[2];
static size_t                   tx_box_bytes[2];
static spinlock_t               tx_box_lock;

#define RX_BOX_SIZE (SHARED_MEM_SIZE / (MAX_NET_DEVICES * 2))
#define TX_BOX_SIZE (SHARED_MEM_SIZE / 4)
#define GET_RX_BOX(DEVICE_INDEX) \
	(shared_mem + (RX_BOX_SIZE * DEVICE_INDEX))
#define GET_TX_BOX(BOX_INDEX) \
	(shared_mem + (SHARED_MEM_SIZE / 2) + (BOX_INDEX * TX_BOX_SIZE))
#define MAX_TX (0x100)
#define DESC_OFFSET (2)

static uint16_t intrepid_next_tx_description(
	struct intrepid_netdevice* ics,
	int* idx_out)
{
	/* we offset the description so that we know 0 is not us transmitting */
	uint16_t description = ics->tx_idx + DESC_OFFSET;
	*idx_out = ics->tx_idx;
	ics->tx_idx++;
	return description;
}

static int intrepid_description_to_idx(uint16_t description)
{
	if (description < DESC_OFFSET || description >= DESC_OFFSET + MAX_TX)
		return -1;

	return description - DESC_OFFSET;
}

/* Returns 1 when we would not have enough space to hold another message of `size` */
static inline int intrepid_tx_box_no_space_for(size_t size)
{
	return (tx_box_bytes[current_tx_box] + size >= TX_BOX_SIZE - 1);
}

static void intrepid_unpause_all_queues(void)
{
	int i;
	for (i = 0; i < MAX_NET_DEVICES; ++i) {
		struct net_device *dev = net_devices[i];
		struct intrepid_netdevice *ics;
		if (dev == NULL)
			continue;

		ics = netdev_priv(dev);
		spin_lock_bh(&ics->lock);
		if (ics->is_stopped) {
			netif_wake_queue(dev);
			ics->is_stopped = 0;
		}
		spin_unlock_bh(&ics->lock);
	}
}

static void intrepid_pause_all_queues(void)
{
	int i;
	for (i = 0; i < MAX_NET_DEVICES; ++i) {
		struct net_device *dev = net_devices[i];
		struct intrepid_netdevice *ics;
		if (dev == NULL)
			continue;

		ics = netdev_priv(dev);
		spin_lock_bh(&ics->lock);
		if (!ics->is_stopped) {
			ics->is_stopped = 1;
			netif_stop_queue(dev);
		}
		spin_unlock_bh(&ics->lock);
	}
}

static netdev_tx_t intrepid_CAN_netdevice_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int ret = NETDEV_TX_OK;
	struct intrepid_netdevice *ics = netdev_priv(dev);
	struct canfd_frame *cf = (struct canfd_frame*)skb->data;
	bool fd = can_is_canfd_skb(skb);
	bool needs_unlock = false;
	bool consumed = false;
	int tx_idx;
	neomessage_can_t msg = {0};

	if (can_dropped_invalid_skb(dev, skb)) {
		pr_debug("intrepid: dropping invalid frame on %s\n", dev->name);
		goto exit;
	}

	spin_lock_bh(&tx_box_lock);
	needs_unlock = true;

	if (unlikely(ics->is_stopped)) {
		pr_err("intrepid: in xmit but device is stopped\n");
		if (intrepid_tx_box_no_space_for(sizeof(neomessage_can_t) + CANFD_MTU)) {
			ret = NETDEV_TX_BUSY;
			goto exit;
		}
		pr_warn("intrepid: device should not have been stopped, waking all\n");
		intrepid_unpause_all_queues();
	}

	/* convert the canfd_frame to a neomessage_can_t */
	if (cf->can_id & CAN_EFF_FLAG) {
		msg.arbid = cf->can_id & CAN_EFF_MASK;
		msg.status.extendedFrame = true;
	} else {
		msg.arbid = cf->can_id & CAN_SFF_MASK;
	}

	if (fd) {
		msg.status.canfdFDF = true;
		if (cf->flags & CANFD_BRS)
			msg.status.canfdBRS = true;
		if (cf->flags & CANFD_ESI)
			msg.status.canfdESI = true;
	}

	if (cf->can_id & CAN_RTR_FLAG) {
		if (unlikely(fd)) {
			pr_info("intrepid: tried to send RTR frame on CANFD %s\n", dev->name);
			goto exit;
		}
		msg.status.remoteFrame = true;
	}

	msg.length = cf->len;
	msg.netid = dev->base_addr;
	msg.type = ICSNEO_NETWORK_TYPE_CAN;

	if (intrepid_tx_box_no_space_for(sizeof(neomessage_can_t) + msg.length)) {
		/* This should never happen, the queue should be paused before this */
		ssize_t offset = TX_BOX_SIZE;
		offset -= (tx_box_bytes[current_tx_box] + sizeof(neomessage_can_t) + msg.length);
		pr_err("intrepid: %zu length message caused NETDEV_TX_BUSY (%zd)\n", msg.length, offset);
		ret = NETDEV_TX_BUSY;
		goto exit;
	}
	msg.description = intrepid_next_tx_description(ics, &tx_idx);
	can_put_echo_skb(skb, dev, tx_idx
#if KERNEL_CAN_ECHO_TRACKS_LEN
		, msg.length
#endif
	);
	consumed = true;

	/* Copy the message into the usermode box */
	memcpy(tx_boxes[current_tx_box] + tx_box_bytes[current_tx_box], &msg, sizeof(neomessage_can_t));
	tx_box_bytes[current_tx_box] += sizeof(neomessage_can_t);
	memcpy(tx_boxes[current_tx_box] + tx_box_bytes[current_tx_box], cf->data, msg.length);
	tx_box_bytes[current_tx_box] += msg.length;
	tx_box_count[current_tx_box]++;

	/* If we might not be able to fit the next message, let's lock until we can to prevent NETDEV_TX_BUSY */
	if (intrepid_tx_box_no_space_for(sizeof(neomessage_can_t) + CANFD_MTU))
		intrepid_pause_all_queues();
exit:
	if (ret == NETDEV_TX_OK && !consumed)
		consume_skb(skb);
	wake_up_interruptible(&tx_wait);
	if (needs_unlock)
		spin_unlock_bh(&tx_box_lock);
	return ret;
}

static netdev_tx_t intrepid_ETH_netdevice_xmit(struct sk_buff *skb, struct net_device *dev) {
	int ret = NETDEV_TX_OK;
	struct intrepid_netdevice *ics = netdev_priv(dev);
	bool needs_unlock = false;
	bool consumed = false;
	int tx_idx;
	neomessage_eth_t msg = {0};

	spin_lock_bh(&tx_box_lock);
	needs_unlock = true;

	if (unlikely(ics->is_stopped)) {
		pr_err("intrepid: in xmit but device is stopped\n");
		if (intrepid_tx_box_no_space_for(sizeof(neomessage_eth_t) + ETH_DATA_LEN)) {
			ret = NETDEV_TX_BUSY;
			goto exit;
		}
		pr_warn("intrepid: device should not have been stopped, waking all\n");
		intrepid_unpause_all_queues();
	}

	msg.length = skb->len;
	msg.netid = dev->base_addr;
	msg.type = ICSNEO_NETWORK_TYPE_ETHERNET;

	if (intrepid_tx_box_no_space_for(sizeof(neomessage_eth_t) + msg.length)) {
		/* This should never happen, the queue should be paused before this */
		ssize_t offset = TX_BOX_SIZE;
		offset -= (tx_box_bytes[current_tx_box] + sizeof(neomessage_eth_t) + msg.length);
		pr_err("intrepid: %zu length message caused NETDEV_TX_BUSY (%zd)\n", msg.length, offset);
		ret = NETDEV_TX_BUSY;
		goto exit;
	}
	msg.description = intrepid_next_tx_description(ics, &tx_idx);
	consumed = true;

	/* Copy the message into the usermode box */
	memcpy(tx_boxes[current_tx_box] + tx_box_bytes[current_tx_box], &msg, sizeof(neomessage_eth_t));
	tx_box_bytes[current_tx_box] += sizeof(neomessage_eth_t);
	memcpy(tx_boxes[current_tx_box] + tx_box_bytes[current_tx_box], skb->data, skb->len);
	tx_box_bytes[current_tx_box] += msg.length;
	tx_box_count[current_tx_box]++;

	/* If we might not be able to fit the next message, let's lock until we can to prevent NETDEV_TX_BUSY */
	if (intrepid_tx_box_no_space_for(sizeof(neomessage_eth_t) + ETH_DATA_LEN))
		intrepid_pause_all_queues();
exit:
	if (ret == NETDEV_TX_OK && !consumed)
		consume_skb(skb);
	wake_up_interruptible(&tx_wait);
	if (needs_unlock)
		spin_unlock_bh(&tx_box_lock);
	return ret;
}

static int intrepid_netdevice_stop(struct net_device *dev)
{
	struct intrepid_netdevice *ics = netdev_priv(dev);

	spin_lock_bh(&ics->lock);
	netif_stop_queue(dev);
	netif_carrier_off(dev);
	spin_unlock_bh(&ics->lock);

	return 0;
}

static int intrepid_netdevice_open(struct net_device *dev)
{
	netif_start_queue(dev);
	netif_carrier_on(dev);
	return 0;
}

// static int intrepid_netdevice_change_mtu(struct net_device *dev, int new_mtu)
// {
// 	return -EINVAL;
// }

//CAN
static const struct net_device_ops intrepid_CAN_netdevice_ops = {
	.ndo_open               = intrepid_netdevice_open,
	.ndo_stop               = intrepid_netdevice_stop,
	.ndo_start_xmit         = intrepid_CAN_netdevice_xmit,
	//.ndo_change_mtu         = intrepid_netdevice_change_mtu,
};

//ETH
static const struct net_device_ops intrepid_ETH_netdevice_ops = {
	.ndo_open               = intrepid_netdevice_open,
	.ndo_stop               = intrepid_netdevice_stop,
	.ndo_start_xmit         = intrepid_ETH_netdevice_xmit,
	//.ndo_change_mtu         = intrepid_netdevice_change_mtu,
};

static struct net_device* intrepid_get_dev_by_index(int index)
{
	if (index < 0 || index >= MAX_NET_DEVICES)
		return NULL;

	return net_devices[index];
}

static int intrepid_remove_can_if(int index)
{
	struct net_device *device = intrepid_get_dev_by_index(index);
	if (!device)
		return -EINVAL;

	if (index != device->base_addr)
		pr_warn("intrepid: Index of device %ld does not match given index %d\n", device->base_addr, index);

	pr_info("intrepid: Removing device %d %s 0x%p\n", index, device->name, device);

	unregister_candev(device);

	net_devices[index] = NULL;

	pr_info("intrepid: Removed device %d\n", index);

	return 0;
}

static int intrepid_set_bittiming(struct net_device *netdev)
{
	struct intrepid_netdevice *dev = netdev_priv(netdev);
	struct can_bittiming *bt = &dev->can.bittiming;

	dev_dbg(&netdev->dev, "bitrate %d sample_point %d tq %d sjw %d phase1 %d phase2 %d prop %d brp %d",
		bt->bitrate, bt->sample_point, bt->tq, bt->sjw, bt->phase_seg1, bt->phase_seg2, bt->prop_seg, bt->brp);

	dev->bitrate_changed = 1;
	wake_up_interruptible(&tx_wait);
	return 0;
}

static int intrepid_set_data_bittiming(struct net_device *netdev)
{
	struct intrepid_netdevice *dev = netdev_priv(netdev);
	struct can_bittiming *bt = &dev->can.data_bittiming;

	dev_dbg(&netdev->dev, "bitrate %d sample_point %d tq %d sjw %d phase1 %d phase2 %d prop %d brp %d",
		bt->bitrate, bt->sample_point, bt->tq, bt->sjw, bt->phase_seg1, bt->phase_seg2, bt->prop_seg, bt->brp);

	dev->bitrate_changed = 1;
	wake_up_interruptible(&tx_wait);
	return 0;
}

static int intrepid_bitrates[] = {
	20000,
	33000,
	50000,
	62000,
	83000,
	100000,
	125000,
	250000,
	500000,
	666000,
	800000,
	1000000
};

static int intrepid_data_bitrates[] = {
	20000,
	33000,
	50000,
	62000,
	83000,
	100000,
	125000,
	250000,
	500000,
	666000,
	800000,
	1000000,
	2000000,
	4000000,
	5000000,
	6667000,
	8000000,
	10000000
};

static int intrepid_add_can_if(struct intrepid_netdevice **result, const char *requestedName)
{
	// The `requestedName` parameter is always NULL if KERNEL_SUPPORTS_ALIASES is false
#if KERNEL_SUPPORTS_ALIASES
	size_t aliasLen = 0;
#endif
	int i;
	int ret = -EPERM;
	struct net_device *dev = NULL;
	struct intrepid_netdevice *ics = NULL;

	*result = NULL;

	for (i = 0; i < MAX_NET_DEVICES; i++) {
		if (net_devices[i] == NULL)
			break;
	}

	if (i >= MAX_NET_DEVICES) {
		pr_alert("intrepid: No more netdevices available\n");
		ret = -ENFILE;
		goto exit;
	}

	dev = alloc_candev(sizeof(*ics), MAX_TX);
	if (!dev) {
		pr_alert("intrepid: Could not allocate candev\n");
		goto exit;
	}

	dev->base_addr          = i;
	dev->flags             |= IFF_ECHO;
#if KERNEL_CHECKS_MTU_RANGE
	dev->min_mtu            = CAN_MTU;
	dev->max_mtu            = CANFD_MTU;
#endif
	dev->mtu                = CANFD_MTU; /* TODO: Check CAN-FD support from usermode daemon */
	dev->netdev_ops         = &intrepid_CAN_netdevice_ops;
#if KERNEL_SUPPORTS_ALIASES
	if (requestedName && ((aliasLen = strlen(requestedName)) > 0) && aliasLen < IFALIASZ) {
		dev->ifalias = kzalloc(sizeof(struct dev_ifalias) + aliasLen + 1, GFP_KERNEL);
		if (dev->ifalias == NULL) {
			pr_alert("intrepid: Could not allocate space for ifalias %zu\n", sizeof(struct dev_ifalias));
		} else {
			strncpy(dev->ifalias->ifalias, requestedName, aliasLen + 1);
			pr_info("intrepid: %s alias set to %s\n", dev->name, requestedName);
		}
	}
#endif
	ics                  = netdev_priv(dev);
	ics->dev             = dev;
	ics->is_stopped      = 0;
	ics->from_user       = GET_RX_BOX(i); /* incoming rx messages */
	ics->tx_idx          = 0;

	if (VER_MIN_FROM_INT(client_version) > 1) {
		ics->can.bitrate_const = intrepid_bitrates;
		ics->can.bitrate_const_cnt = ARRAY_SIZE(intrepid_bitrates);
		ics->can.data_bitrate_const = intrepid_data_bitrates;
		ics->can.data_bitrate_const_cnt = ARRAY_SIZE(intrepid_data_bitrates);
		ics->can.do_set_bittiming = intrepid_set_bittiming;
		ics->can.do_set_data_bittiming = intrepid_set_data_bittiming;
	}
	ics->can.state = CAN_STATE_ERROR_ACTIVE;
	ics->can.ctrlmode_supported = CAN_CTRLMODE_FD;

	spin_lock_init(&ics->lock);

	ret = register_candev(dev);
	if (ret) {
		pr_alert("intrepid: Could not register candev\n");
		free_candev(dev);
		goto exit;
	}

	net_devices[i] = dev;
	*result = ics;

	ret = i;

	pr_info("intrepid: Allocated new netdevice %s @ %d\n", dev->name, ret);
exit:
	return ret;

}

static int intrepid_fill_canerr_frame_from_neomessage(
	struct net_device_stats *stats,
	struct can_frame *cf,
	const neomessage_can_t *msg)
{
	if (msg->status.transmitMessage) {
		stats->tx_errors++;

		if (msg->status.lostArbitration) {
			cf->can_id |= CAN_ERR_LOSTARB;
			cf->data[0] = CAN_ERR_LOSTARB_UNSPEC;
		} else if (msg->status.vsiTXUnderrun) {
			cf->can_id |= CAN_ERR_ACK;
		} else {
			cf->can_id |= CAN_ERR_PROT | CAN_ERR_BUSERROR;
			cf->data[2] = CAN_ERR_PROT_TX;
		}
	} else {
		stats->rx_over_errors++;
		stats->rx_errors++;

		if (msg->status.canBusShortedPlus) {
			cf->can_id |= CAN_ERR_TRX | CAN_ERR_BUSERROR;
			cf->data[4] = CAN_ERR_TRX_CANH_SHORT_TO_BAT | CAN_ERR_TRX_CANL_SHORT_TO_BAT;
		} else {
			cf->can_id |= CAN_ERR_BUSERROR;
		}
	}

	return 0;
}

static int intrepid_fill_canfd_frame_from_neomessage(
	struct net_device_stats *stats,
	struct canfd_frame *cf,
	const neomessage_can_t *msg,
	const uint8_t *data)
{
	if (msg->status.extendedFrame)
		cf->can_id |= (msg->arbid & CAN_EFF_MASK) | CAN_EFF_FLAG;
	else
		cf->can_id |= msg->arbid & CAN_SFF_MASK;

	if (msg->status.canfdBRS)
		cf->flags |= CANFD_BRS;
	if (msg->status.canfdESI)
		cf->flags |= CANFD_ESI;
	cf->len = msg->length;
	memcpy(cf->data, data, cf->len);

	stats->rx_bytes += cf->len;
	stats->rx_packets++;

	return 0;
}

static int intrepid_fill_can_frame_from_neomessage(
	struct net_device_stats *stats,
	struct can_frame *cf,
	const neomessage_can_t *msg,
	const uint8_t *data)
{
	if (msg->status.extendedFrame)
		cf->can_id |= (msg->arbid & CAN_EFF_MASK) | CAN_EFF_FLAG;
	else
		cf->can_id |= msg->arbid & CAN_SFF_MASK;

	if (msg->status.remoteFrame)
		cf->can_id |= CAN_RTR_FLAG;

	if (unlikely(msg->length > 8))
		return -1;

	cf->can_dlc = msg->length;
	memcpy(cf->data, data, cf->can_dlc);

	stats->rx_bytes += cf->can_dlc;
	stats->rx_packets++;

	return 0;
}

/* Returns true if this message was handled as a transmit receipt.
 * If false is returned, this message should be handled as a receive
 * message, regardless of the transmit flag.
 */
static bool handle_CAN_transmit_receipt(
	struct net_device *device,
	const neomessage_can_t *msg,
	const uint8_t *data,
	struct net_device_stats *stats)
{
	int length;
	int tx_idx;

	if (!msg->status.transmitMessage)
		return false;

	tx_idx = intrepid_description_to_idx(msg->description);

	/* not transmitted by us, maybe by CoreMini */
	/* just handle it as a receive */
	if (tx_idx < 0)
		return false;

	/* unsuccessful transmits */
	/* stats are handled in intrepid_fill_canerr_frame_from_neomessage */
	if (msg->status.globalError) {
		can_free_echo_skb(device, tx_idx
#if KERNEL_CAN_ECHO_TRACKS_LEN
			, NULL
#endif
		);
		return false;
	}

	length = can_get_echo_skb(device, tx_idx
#if KERNEL_CAN_ECHO_TRACKS_LEN
		, NULL
#endif
	);
	stats->tx_packets++;
	stats->tx_bytes += length;
	return true;
}

static bool handle_ETH_transmit_receipt(
	const neomessage_eth_t *msg,
	const uint8_t *data,
	struct net_device_stats *stats)
{
	int tx_idx;

	if (!msg->status.transmitMessage) {
		return false;
	}

	tx_idx = intrepid_description_to_idx(msg->description);

	/* not transmitted by us, maybe by CoreMini */
	/* just handle it as a receive */
	if (tx_idx < 0)
		return false;

	/* unsuccessful transmits */
	if (msg->status.globalError) {
		struct sk_buff *skb;
		kfree_skb(&skb[tx_idx]);
		return false;
	}

	stats->tx_packets++;
	stats->tx_bytes += msg->length;

	return true;
}

static int intrepid_remove_eth_if(int index)
{
	struct net_device *device = intrepid_get_dev_by_index(index);
	if (!device)
		return -EINVAL;

	if (index != device->base_addr)
		pr_warn("intrepid: Index of device %ld does not match given index %d\n", device->base_addr, index);

	pr_info("intrepid: Removing device %d %s 0x%p\n", index, device->name, device);

	unregister_netdev(device);

	net_devices[index] = NULL;

	pr_info("intrepid: Removed device %d\n", index);

	return 0;
}

static int intrepid_add_eth_if(struct intrepid_netdevice **result, const char *requestedName)
{
	// The `requestedName` parameter is always NULL if KERNEL_SUPPORTS_ALIASES is false
#if KERNEL_SUPPORTS_ALIASES
	size_t aliasLen = 0;
#endif
	int i = 0;
	int ret = -EPERM;
	struct net_device *dev = NULL;
	struct intrepid_netdevice *ics = NULL;

	*result = NULL;
	// Find the first NULL position in net_devices
	for (i = 0; i < MAX_NET_DEVICES; ++i) {
		if (net_devices[i] == NULL) {
			break;
		}
	}

	// If for loop never broke, there is no room in net_devices
	if (i == MAX_NET_DEVICES) {
		pr_alert("intrepid: No more netdevices available\n");
		ret = -ENFILE;
		goto exit;
	}

	// Allocates and sets an ethernet device
	dev = alloc_etherdev(sizeof(*ics));

	if (!dev) {
		pr_alert("intrepid: Could not allocate ethernet device\n");
		goto exit;
	}

	dev->base_addr = i;
	dev->flags |= IFF_BROADCAST | IFF_MULTICAST | IFF_RUNNING;
	dev->operstate = IF_OPER_UP;
#if KERNEL_CHECKS_MTU_RANGE
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_MAX_MTU;
#endif
	dev->mtu = ETH_DATA_LEN;
	dev->netdev_ops = &intrepid_ETH_netdevice_ops;
#if KERNEL_SUPPORTS_ALIASES
	if (requestedName && ((aliasLen = strlen(requestedName)) > 0) && aliasLen < IFALIASZ) {
		dev->ifalias = kzalloc(sizeof(struct dev_ifalias) + aliasLen + 1, GFP_KERNEL);
		if (dev->ifalias == NULL) {
			pr_alert("inrepid: Could not allocate space for ifalias %zu\n", sizeof(struct dev_ifalias));
		}
		else {
			strncpy(dev->ifalias->ifalias, requestedName, aliasLen + 1);
			pr_info("intrepid: %s alias set to %s\n", dev->name, requestedName);
		}
	}
#endif
	eth_hw_addr_random(dev);

	ics = netdev_priv(dev);
	ics->dev = dev;
	ics->is_stopped = 0;
	ics->from_user = GET_RX_BOX(i);
	ics->tx_idx = 0;

	spin_lock_init(&ics->lock);

	ret = register_netdev(dev);

	if (ret) {
		pr_alert("intrepid: Could not register ethernet device\n");
		free_netdev(dev);
		goto exit;
	}

	net_devices[i] = dev;
	*result = ics;

	ret = i;

	pr_info("intrepid: Allocated new netdevice %s @ %d\n", dev->name, ret);
exit:
	return ret;
}

static int intrepid_fill_eth_frame_from_neomessage(
	struct net_device_stats *stats,
	const neomessage_eth_t *msg,
	const uint8_t *data,
	struct sk_buff *skb)
{
	if (unlikely(msg->length > (ETH_FRAME_LEN + ETH_FCS_LEN))) {
		stats->rx_dropped++;
		return -1;
	}

	if (unlikely(skb == NULL)) {
		stats->rx_dropped++;
		return -1;
	}

	skb_put_data(skb, data, msg->length);
	skb->protocol = eth_type_trans(skb, skb->dev);
	stats->rx_bytes += msg->length;
	stats->rx_packets++;

	return 0;
}

static struct sk_buff *intrepid_skb_from_neomessage(
	struct net_device *device,
	const neomessage_frame_t *msg_generic,
	const uint8_t *data,
	struct net_device_stats *stats)
{
	struct sk_buff *skb = NULL;
	int ret = 0;

	/* input validation */
	if (unlikely(device == NULL || msg_generic == NULL || data == NULL || stats == NULL)) {
		stats->rx_dropped++;
		pr_debug("intrepid: Dropping message on %s, skb from neomessage input validation failed", device->name);
		goto out;
	}
	switch (msg_generic->type) {
		case ICSNEO_NETWORK_TYPE_CAN:
			{
				struct canfd_frame* cf = NULL;
				const neomessage_can_t* can_msg = NULL;
				can_msg = (const neomessage_can_t*)msg_generic;
				if (handle_CAN_transmit_receipt(device, can_msg, data, stats))
					goto out;
				if (can_msg->status.globalError)
					skb = alloc_can_err_skb(device, (struct can_frame**)&cf);
				else if (can_msg->status.canfdFDF)
					skb = alloc_canfd_skb(device, &cf);
				else
					skb = alloc_can_skb(device, (struct can_frame**)&cf);

				/* if this message is handled as a transmit receipt,
				* don't turn it into a receive skb here.
				*/
				if (unlikely(skb == NULL)) {
					stats->rx_dropped++;
					pr_warn("intrepid: Dropping message on %s, skb allocation failed", device->name);
					goto out;
				}

				if (can_msg->status.globalError)
					ret = intrepid_fill_canerr_frame_from_neomessage(
					stats,
					(struct can_frame*)cf,
					(const neomessage_can_t*)can_msg);
				else if (can_msg->status.canfdFDF)
					ret = intrepid_fill_canfd_frame_from_neomessage(
						stats,
						cf,
						(const neomessage_can_t*)can_msg,
						data);
				else
					ret = intrepid_fill_can_frame_from_neomessage(
						stats,
						(struct can_frame*)cf,
						(const neomessage_can_t*)can_msg,
						data);
			}
			break;
		case ICSNEO_NETWORK_TYPE_ETHERNET:
			{
				const neomessage_eth_t *msg = (const neomessage_eth_t*)msg_generic;
				if (handle_ETH_transmit_receipt(msg, data, stats))
					goto out;
				skb = netdev_alloc_skb_ip_align(device, msg->length);
				if (unlikely(skb == NULL)) {
					stats->rx_dropped++;
					pr_warn("intrepid: Dropping message on %s, skb allocation failed", device->name);
					goto out;
				}

				ret = intrepid_fill_eth_frame_from_neomessage(stats, msg, data, skb);
			}
			break;
		default:
			pr_debug("intrepid: Dropping message on %s, invalid type %d", device->name, msg_generic->type);
			goto out;
		}

	if (unlikely(ret != 0)) {
		pr_debug("intrepid: Dropping message on %s, frame fill failed", device->name);
		goto out;
	}
out:
	return skb;
}

static int intrepid_read_messages(int device_index, unsigned int count)
{
	const uint8_t* currentPosition;
	struct intrepid_netdevice* ics;
	struct net_device_stats *stats;
	struct net_device *device = intrepid_get_dev_by_index(device_index);
	if (!device)
		return -EINVAL;

	stats = &device->stats;
	ics = netdev_priv(device);
	spin_lock_bh(&ics->lock);
	currentPosition = ics->from_user;
	if (count != 1)
		pr_info("intrepid: reading %d messages\n", count);

	/* ics->from_user is where usermode copied in some neomessage_ts that need
	 * to be pumped into the receive plumbing of the interface. loop over them,
	 * converting neomessage_t to a CAN sk_buff */

	while (count--) {
		const neomessage_frame_t *msg;
		const uint8_t *data;
		struct sk_buff *skb;
		int ret = 0;

		msg = (const neomessage_frame_t*)currentPosition;
		currentPosition += sizeof(neomessage_frame_t);
		data = currentPosition;
		currentPosition += msg->length;

		skb = intrepid_skb_from_neomessage(device, msg, data, stats);
		/* pass along the converted message to the kernel for dispatch */
		if (skb != NULL)
			ret = netif_rx(skb);

		if (ret == NET_RX_DROP)
			pr_debug("intrepid: Dropping message on %s, dropped by kernel", device->name);
	}

	spin_unlock_bh(&ics->lock);
	return 0;
}

static long intrepid_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	if (mutex_lock_interruptible(&ioctl_mutex)) {
		pr_info("intrepid: ioctl handler interrupted\n");
		return -ERESTARTSYS;
	}

	switch(cmd) {
		case SIOCSADDCANIF: {
			struct intrepid_netdevice *result = NULL;
#if KERNEL_SUPPORTS_ALIASES
			char requestedNameBuffer[IFALIASZ] = {0};
			char* requestedName = NULL;
			int bytesNotCopied = 0;
			if ((void __user*)arg != NULL) {
				bytesNotCopied = copy_from_user(requestedNameBuffer, (void __user*)arg, IFALIASZ);
				if (bytesNotCopied != 0)
					pr_warn("intrepid: %d bytes not copied for alias", bytesNotCopied);
				requestedName = requestedNameBuffer;
			}
			ret = intrepid_add_can_if(&result, requestedName);
#else
			ret = intrepid_add_can_if(&result, NULL);
#endif
			break;
		}
		case SIOCSREMOVECANIF:
			ret = intrepid_remove_can_if (arg);
			break;
		case SIOCSBAUDRATE: {
			struct baudrate_info {
				int handle;
				int64_t baudrates[2];
			} info;
			ret = copy_from_user(&info, (void __user*)arg, sizeof(info));
			if (ret)
				break;
			struct net_device *device = intrepid_get_dev_by_index(info.handle);
			if (device == NULL)
				break;
			struct intrepid_netdevice *ics = netdev_priv(device);
			ics->can.bittiming.bitrate = info.baudrates[0];
			ics->can.data_bittiming.bitrate = info.baudrates[1];
			break;
		}
		case SIOCSADDETHIF: {
			struct intrepid_netdevice *result = NULL;
#if KERNEL_SUPPORTS_ALIASES
			char requestedNameBuffer[IFALIASZ] = {0};
			char* requestedName = NULL;
			int bytesNotCopied = 0;
			if ((void __user*)arg != NULL) {
				bytesNotCopied = copy_from_user(requestedNameBuffer, (void __user*)arg, IFALIASZ);
				if (bytesNotCopied != 0)
					pr_warn("intrepid: %d bytes not copied for alias", bytesNotCopied);
				requestedName = requestedNameBuffer;
			}
			ret = intrepid_add_eth_if(&result, requestedName);
#else
			ret = intrepid_add_eth_if(&result, NULL);
#endif
			break;
		}
		case SIOCSREMOVEETHIF:
			ret = intrepid_remove_eth_if (arg);
			break;
		case SIOCGSHAREDMEMSIZE:
			ret = SHARED_MEM_SIZE;
			break;
		case SIOCGMAXIFACES:
			ret = MAX_NET_DEVICES;
			break;
		case SIOCGVERSION:
			ret = KO_VERSION_INT;
			break;
		case SIOCGCLIENTVEROK:
			client_version = arg;
			if (VER_MAJ_FROM_INT(arg) == 3 && VER_MIN_FROM_INT(arg) >= 1 && VER_PATCH_FROM_INT(arg) >= 0)
				ret = 0; /* ok to start */
			else
				ret = 1;
			break;
		case SIOCSMSGSWRITTEN: {
			int          index = (int)(arg >> 16);
			unsigned int count = (int)(arg & 0xffff);

			ret = intrepid_read_messages(index, count);
			break;
		}
	} /* end switch (cmd) */

	mutex_unlock(&ioctl_mutex);
	return ret;
}

/* when the mmap()ed pages are first accesed by usermode there will be a page fault.
 * here we simply linerally map in the big vmalloc() we got.
 *
 * Starting in kernel version 4.11, (struct vm_operations_struct *)->fault() no
 * longer takes the vma parameter (since it resides in vmf) */
static vm_fault_t intrepid_vm_fault(
#if KERNEL_FAULT_TAKES_VMA
	struct vm_area_struct *vma,
#endif
	struct vm_fault *vmf)
{
	vmf->page = vmalloc_to_page(shared_mem + (vmf->pgoff << PAGE_SHIFT));
	get_page(vmf->page); /* increment reference count, very important */

	return 0;
}

static struct vm_operations_struct intrepid_vm_ops = {
	.fault = intrepid_vm_fault
};

static int intrepid_dev_mmap(struct file* fp, struct vm_area_struct *vma)
{
	vma->vm_ops = &intrepid_vm_ops;
	return 0;
}

static int intrepid_dev_open(struct inode *ip, struct file *fp)
{
	if (is_open)
		return -EIO;

	is_open = 1;
	return 0;
}

/* called when /dev/intrepid_netdevice is closed -- delete any created interfaces */
static int intrepid_dev_release(struct inode *ip, struct file *fp)
{
	int i;

	if (!is_open)
		return -EIO;

	wake_up_interruptible(&tx_wait);

	for (i = 0; i < MAX_NET_DEVICES; i++) {
		if (net_devices[i] != NULL) {
			if (net_devices[i]->type == ARPHRD_CAN)
				intrepid_remove_can_if(i);
			else if (net_devices[i]->type == ARPHRD_ETHER)
				intrepid_remove_eth_if(i);
		}
	}

	is_open = 0;
	return 0;
}

/* Re-use the pending_tx_info struct to send changed bitrates to userland
 * Set the box index to -(dev_id) and encode the rest of the data in the count
 * and bytes fields.
 * count is the bitrate value
 * bytes is the data bitrate value. */
static int check_bitrate_change(struct intrepid_pending_tx_info *info)
{
	int i;
	struct intrepid_netdevice *ics;

	for (i = 0; i < MAX_NET_DEVICES; i++) {
		if (net_devices[i] == NULL || net_devices[i]->type != ARPHRD_CAN)
			continue;
		ics = netdev_priv(net_devices[i]);

		if (ics->bitrate_changed) {
			info->tx_box_index = -(i + 1);
			info->count = ics->can.bittiming.bitrate;
			info->bytes = ics->can.data_bittiming.bitrate;
			ics->bitrate_changed = 0;
			return 1;
		}
	}

	return 0;
}

/* usermode uses read() to get the current size of the tx buffer. we use a ping pong buffer
 * so the user doesn't have to worry about the data changing out from under them while
 * still avoiding a full copy to user. the ping pong flips on every call to this func */
static ssize_t intrepid_dev_read(struct file *fp, char *buffer, size_t len, loff_t *offset)
{
	struct intrepid_pending_tx_info info;
	int ret;

	if (len < sizeof(info))
		return -EFAULT;

	/* check if we have to send a bitrate change */
	if (VER_MIN_FROM_INT(client_version) > 1) {
		if (check_bitrate_change(&info)) {
			if (copy_to_user(buffer, &info, sizeof(info)))
				return -EFAULT;
			return sizeof(info);
		}
	}

	spin_lock_bh(&tx_box_lock);

	/* fill out the info for the user */
	info.tx_box_index = current_tx_box;
	info.count        = tx_box_count[current_tx_box];
	info.bytes        = tx_box_bytes[current_tx_box];

	ret = copy_to_user(buffer, &info, sizeof(info));

	/* if we were full, unpause the queue */
	intrepid_unpause_all_queues();

	tx_box_count[current_tx_box] = 0;
	tx_box_bytes[current_tx_box] = 0;

	/* swap to the other buffer. once we unlock new tx messages will go to the new box */
	current_tx_box = current_tx_box == 0 ? 1 : 0;

	spin_unlock_bh(&tx_box_lock);

	if (ret != 0)
		return -EFAULT;
	return sizeof(info);
}

static unsigned int intrepid_dev_poll(struct file *fp, poll_table *wait)
{
	/* tx_wait is woken up in intrepid_netdevice_xmit. remember we're backwards here;
	 * the usermode is waiting to read messages to subsequently transmit out */
	poll_wait(fp, &tx_wait, wait);

	if (tx_box_count[current_tx_box] > 0)
		return POLLIN | POLLRDNORM;

	if (VER_MIN_FROM_INT(client_version) > 1) {
		int i;
		for (i = 0; i < MAX_NET_DEVICES; i++) {
			if (net_devices[i] == NULL || net_devices[i]->type != ARPHRD_CAN)
				continue;
			struct intrepid_netdevice *ics = netdev_priv(net_devices[i]);

			if (ics->bitrate_changed)
				return POLLIN | POLLRDNORM;
		}
	}

	return 0;
}

static struct file_operations intrepid_fops = {
	.open           = intrepid_dev_open,
	.read           = intrepid_dev_read,
	.release        = intrepid_dev_release,
	.mmap           = intrepid_dev_mmap,
	.unlocked_ioctl = intrepid_dev_ioctl,
	.poll           = intrepid_dev_poll
};

static __init int intrepid_init(void)
{
	int ret;
	pr_info("intrepid: %s %s\n", KO_DESC, KO_VERSION);

	BUILD_BUG_ON_MSG(sizeof(neomessage_t) != (56 + sizeof(void*) + sizeof(size_t)),
		"neomessage_t size is incorrect!");
	BUILD_BUG_ON_MSG(sizeof(neomessage_frame_t) != sizeof(neomessage_t),
		"All types of neomessage_t must be the same size! (Base frame is not)");
	BUILD_BUG_ON_MSG(sizeof(neomessage_can_t) != sizeof(neomessage_t),
		"All types of neomessage_t must be the same size! (CAN is not)");
	BUILD_BUG_ON_MSG(sizeof(neomessage_can_error_t) != sizeof(neomessage_t),
		"All types of neomessage_t must be the same size! (CAN error is not)");
	BUILD_BUG_ON_MSG(sizeof(neomessage_eth_t) != sizeof(neomessage_t),
		"All types of neomessage_t must be the same size! (Ethernet is not)");

	is_open = 0;

	/* this is the shared memory used to transfer between us and the user daemon */
	shared_mem = vmalloc_user(SHARED_MEM_SIZE);
	if (!shared_mem) {
		ret = -ENOMEM;
		goto exit;
	}

	/* make space for up to MAX_NET_DEVICES devices */
	net_devices = kzalloc(sizeof(struct net_device*) * MAX_NET_DEVICES, GFP_KERNEL);
	if (!net_devices) {
		ret = -ENOMEM;
		goto free_shared_mem;
	}

	/* to make our ioctls blocking we wrap the handlers in a global mutex */
	mutex_init(&ioctl_mutex);

	/* this is the queue of processes waiting to read from our device. we'll signal
	 * once some tx messages are ready */
	init_waitqueue_head(&tx_wait);

	tx_boxes[0]     = GET_TX_BOX(0);
	tx_boxes[1]     = GET_TX_BOX(1);
	tx_box_bytes[0] = 0;
	tx_box_bytes[1] = 0;
	tx_box_count[0] = 0;
	tx_box_count[1] = 0;
	current_tx_box  = 0;
	spin_lock_init(&tx_box_lock);

	/* create /dev/intrepid_netdevice */

	major_number = register_chrdev(0, INTREPID_DEVICE_NAME, &intrepid_fops);
	if (major_number < 0) {
		pr_alert("intrepid: failed to register major number, got %d\n",
			major_number);
		return -1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	intrepid_dev_class = class_create(THIS_MODULE, INTREPID_CLASS_NAME);
#else
	intrepid_dev_class = class_create(INTREPID_CLASS_NAME);
#endif
	if (IS_ERR(intrepid_dev_class)) {
		ret = PTR_ERR(intrepid_dev_class);
		pr_alert("intrepid: failed to create device class, got %d\n", ret);
		unregister_chrdev(major_number, INTREPID_DEVICE_NAME);
		goto free_net_devices;
	}

	intrepid_dev = device_create(intrepid_dev_class, NULL,
		MKDEV(major_number, 0), NULL, INTREPID_DEVICE_NAME);
	if (IS_ERR(intrepid_dev)) {
		ret = PTR_ERR(intrepid_dev);
		pr_alert("intrepid: failed to create device, got %d\n", ret);
		class_destroy(intrepid_dev_class);
		unregister_chrdev(major_number, INTREPID_DEVICE_NAME);
		goto free_net_devices;
	}

	ret = 0;
	pr_info("intrepid: created %s\n", INTREPID_DEVICE_NAME);
exit:
	return ret;

free_net_devices:
	kfree(net_devices);
free_shared_mem:
	vfree(shared_mem);
	return ret;
}

static __exit void intrepid_exit(void)
{
	int i;
	pr_info("intrepid: exit\n");

	device_destroy(intrepid_dev_class, MKDEV(major_number, 0));
	class_unregister(intrepid_dev_class);
	class_destroy(intrepid_dev_class);
	unregister_chrdev(major_number, INTREPID_DEVICE_NAME);

	for (i = 0; i < MAX_NET_DEVICES; i++) {
		if (net_devices[i] != NULL) {
			if (net_devices[i]->type == ARPHRD_CAN)
				intrepid_remove_can_if(i);
			else if (net_devices[i]->type == ARPHRD_ETHER)
				intrepid_remove_eth_if(i);
		}
	}

	kfree(net_devices);
	net_devices = NULL;

	vfree(shared_mem);
	shared_mem = NULL;
}

module_init(intrepid_init);
module_exit(intrepid_exit);

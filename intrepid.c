/*
 * intrepid.c - Netdevice driver for Intrepid CAN/Ethernet devices
 *
 * Copyright (c) 2016 Intrepid Control Systems, Inc.
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

#define KO_DESC "Netdevice driver for Intrepid CAN/Ethernet devices"
#define KO_VERSION "1.0"

MODULE_DESCRIPTION(KO_DESC);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jeffrey Quesnelle <jeffq@intrepidcs.com>");
MODULE_VERSION(KO_VERSION);

#define INTREPID_DEVICE_NAME            "intrepid_netdevice"
#define INTREPID_CLASS_NAME             "intrepid"
#define MAX_NET_DEVICES                 16
#define SHARED_MEM_SIZE                 0x100000

#define SIOCSADDIF                      0x3001
#define SIOCSREMOVEIF                   0x3002
#define SIOCGSHAREDMEMSIZE              0x3003
#define SIOCSMSGSWRITTEN                0x3004
#define SIOCGMAXIFACES                  0x3005

#define SPY_STATUS_GLOBAL_ERR           0x01
#define SPY_STATUS_TX_MSG               0x02
#define SPY_STATUS_XTD_FRAME            0x04
#define SPY_STATUS_REMOTE_FRAME         0x08
#define SPY_STATUS_LOST_ARBITRATION     0x80
#define SPY_STATUS_BUS_SHORTED_PLUS     0x800
#define SPY_STATUS_VSI_TX_UNDERRUN      0x8000000


struct icsSpyMessage {
    unsigned int   StatusBitField;
    unsigned int   StatusBitField2;
    unsigned int   TimeHardware;
    unsigned int   TimeHardware2;
    unsigned int   TimeSystem;
    unsigned int   TimeSystem2;
    unsigned char  TimeStampHardwareID;
    unsigned char  TimeStampSystemID;
    unsigned char  NetworkID;
    unsigned char  NodeID;
    unsigned char  Protocol;
    unsigned char  MessagePieceID;
    unsigned char  ExtraDataPtrEnabled;
    unsigned char  NumberBytesHeader;
    unsigned char  NumberBytesData;
    unsigned char  NetworkID2;
    unsigned short DescriptionID;
    unsigned int   ArbIDOrHeader;
    unsigned char  Data[8];
    union
    {
        struct
        {
            unsigned int StatusBitField3;
            unsigned int StatusBitField4;
        };
        unsigned char  AckBytes[8];
    };
    void*          ExtraDataPtr;
    unsigned char  MiscData;
    unsigned char  Reserved[3];
}  icsSpyMessage;

struct intrepid_pending_tx_info {
        int tx_box_index;
        int count;
};

struct intrepid_netdevice {
        struct can_priv         can;
	struct can_berr_counter bec;
        struct net_device       *dev;
        spinlock_t              lock;
        int                     is_stopped;
        unsigned char           *from_user;
};

static int                      is_open;
static int                      major_number;
static int                      current_tx_box;
static int                      tx_box_count[2];
static unsigned char            *shared_mem;
static unsigned char            *tx_boxes[2];
static struct class             *intrepid_dev_class;
static struct device            *intrepid_dev;
static struct net_device        **net_devices;
static struct mutex             ioctl_mutex;
static spinlock_t               tx_box_lock;
static wait_queue_head_t        tx_wait;

#define RX_BOX_SIZE                (SHARED_MEM_SIZE / (MAX_NET_DEVICES * 2))
#define TX_BOX_SIZE                (SHARED_MEM_SIZE / 4)
#define GET_RX_BOX(DEVICE_INDEX)   (shared_mem + (RX_BOX_SIZE * DEVICE_INDEX))
#define GET_TX_BOX(INDEX)          (shared_mem + (SHARED_MEM_SIZE / 2) + (INDEX * TX_BOX_SIZE))
#define MAX_NUM_RX_MSGS            (RX_BOX_SIZE / sizeof(struct icsSpyMessage))
#define MAX_NUM_TX_MSGS            (TX_BOX_SIZE / sizeof(struct icsSpyMessage))

static netdev_tx_t intrepid_netdevice_xmit(struct sk_buff *skb, struct net_device *dev)
{
        struct net_device_stats *stats = &dev->stats;
        struct intrepid_netdevice *ics = netdev_priv(dev);
        struct can_frame           *cf = (struct can_frame *)skb->data;
        struct icsSpyMessage       msg = {0};
        struct icsSpyMessage      *box;

        stats->tx_packets++;
        stats->tx_bytes = get_can_dlc(cf->can_dlc);

        if (can_dropped_invalid_skb(dev, skb))
        {
                pr_info("intrepid: dropping invalid frame on %s\n", dev->name);
                return NETDEV_TX_OK;
        }

        /* convert the can_frame to an icsSpyMessage */

        if (cf->can_id & CAN_EFF_FLAG)
        {
                msg.ArbIDOrHeader   = cf->can_id & CAN_EFF_MASK;
                msg.StatusBitField  = SPY_STATUS_XTD_FRAME;
        }
        else
                msg.ArbIDOrHeader   = cf->can_id & CAN_SFF_MASK;

        if (cf->can_id & CAN_RTR_FLAG)
                msg.StatusBitField |= SPY_STATUS_XTD_FRAME;
        else
        {
                msg.NumberBytesData = get_can_dlc(cf->can_dlc); /* is can_dlc sanitizied already? */
                memcpy(msg.Data, cf->data, msg.NumberBytesData);
        }

        msg.NumberBytesHeader = 2;
        msg.NetworkID = dev->base_addr;

        /* copy the message over into the usermode box. if this message fills up the box,
         * turn of the queue until the user reads it out */

        spin_lock_bh(&tx_box_lock);

        box = (struct icsSpyMessage*)tx_boxes[current_tx_box];
        memcpy(box + tx_box_count[current_tx_box], &msg, sizeof(struct icsSpyMessage));

        if (++tx_box_count[current_tx_box] == MAX_NUM_TX_MSGS)
        {
                spin_lock_bh(&ics->lock);
                ics->is_stopped = 1;
                netif_stop_queue(dev);
                spin_unlock_bh(&ics->lock);
        }

        spin_unlock_bh(&tx_box_lock);

        wake_up_interruptible(&tx_wait);

        consume_skb(skb);
	return NETDEV_TX_OK;
}

static int intrepid_netdevice_stop(struct net_device *dev)
{
	struct intrepid_netdevice *ics = netdev_priv(dev);

	spin_lock_bh(&ics->lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&ics->lock);

	return 0;
}

static int intrepid_netdevice_open(struct net_device *dev)
{
	netif_start_queue(dev);

	return 0;
}

static int intrepid_netdevice_change_mtu(struct net_device *dev, int new_mtu)
{
	return -EINVAL;
}

static const struct net_device_ops intrepid_netdevice_ops = {
	.ndo_open               = intrepid_netdevice_open,
	.ndo_stop               = intrepid_netdevice_stop,
	.ndo_start_xmit         = intrepid_netdevice_xmit,
	.ndo_change_mtu         = intrepid_netdevice_change_mtu,
};

static void intrepid_netdevice_free(struct net_device *dev)
{
        int i;

	i = dev->base_addr;
	free_candev(dev);
	net_devices[i] = NULL;
}

static struct net_device* intrepid_get_dev_by_index(int index)
{
        if (index < 0 || index >= MAX_NET_DEVICES)
                return NULL;

        if (net_devices[index] == NULL)
                return NULL;

        return net_devices[index];
}

static int intrepid_remove_if(int index)
{
        struct net_device *device = intrepid_get_dev_by_index(index);
        if (!device)
                return -EINVAL;

        pr_info("intrepid: Removing device %s\n", device->name);

        unregister_candev(device);

        return 0;
}

static int intrepid_add_if(struct intrepid_netdevice** result)
{
        int i, ret = -EPERM;
        struct net_device *dev = NULL;
        struct intrepid_netdevice *ics = NULL;

        *result = NULL;

        for (i = 0 ; i < MAX_NET_DEVICES ; ++i)
        {
                if (net_devices[i] == NULL)
                        break;
        }

        if (i >= MAX_NET_DEVICES)
        {
                pr_alert("intrepid: No more netdevices available\n");
                ret = -ENFILE;
                goto exit;
        }

        dev = alloc_candev(sizeof(*ics), 0);
        if (!dev)
        {
                pr_alert("intrepid: Could not allocate candev\n");
                goto exit;
        }


        dev->base_addr          = i;
        dev->flags             |= IFF_ECHO;
        dev->netdev_ops         = &intrepid_netdevice_ops;
        dev->destructor         = intrepid_netdevice_free;
        ics                     = netdev_priv(dev);
        ics->dev                = dev;
        ics->is_stopped         = 0;
        ics->from_user          = GET_RX_BOX(i); /* incoming rx messages */

        spin_lock_init(&ics->lock);

        ret = register_candev(dev);
        if (ret)
        {
                pr_alert("intrepid: Could not register candev\n");
                free_candev(dev);
                goto exit;
        }

        net_devices[i] = dev;
        *result = ics;

        ret = i;

        pr_info("intrepid: Allocated new netdevice %s\n", dev->name);
exit:
        return ret;

}

static int intrepid_read_messages(int device_index, unsigned int count)
{
        unsigned int i;
        struct icsSpyMessage* msg;
        struct intrepid_netdevice* ics;
        struct net_device_stats *stats;
        struct net_device *device = intrepid_get_dev_by_index(device_index);
        if (!device)
                return -EINVAL;

        stats   = &device->stats;
        ics     = netdev_priv(device);
        msg     = (struct icsSpyMessage*)ics->from_user;

        if (count > MAX_NUM_RX_MSGS)
                count = MAX_NUM_RX_MSGS;

        /* ics->from_user is where usermode copied in some icsSpyMessages that need
         * to be pumped into the receive plumbing of the interface. loop over them,
         * converting icsSpyMessage to a CAN sk_buff */

        for (i = 0 ; i < count ; ++i, ++msg)
        {
                int               ret;
                int               is_error;
                struct can_frame *cf;
                struct sk_buff   *skb;

                is_error = msg->StatusBitField & SPY_STATUS_GLOBAL_ERR;

                if (is_error)
                        skb = alloc_can_err_skb(device, &cf);
                else
                        skb = alloc_can_skb(device, &cf);

                if (unlikely(skb == NULL))
                {
                        stats->rx_dropped++;
                        WARN_ONCE(1, "intrepid: Dropped message on %s: no memory\n",
                                device->name);
                        continue;
                }

                /* if this is a regular message copy over the data bytes and ID, otherwise for
                 * an error fill out what type of error it is */
                if (is_error)
                {
                        if (msg->StatusBitField & SPY_STATUS_TX_MSG)
                        {
                                if (msg->StatusBitField & SPY_STATUS_LOST_ARBITRATION)
                                {
                                        cf->can_id |= CAN_ERR_LOSTARB;
                                        cf->data[0] = CAN_ERR_LOSTARB_UNSPEC;
                                }
                                else if (msg->StatusBitField & SPY_STATUS_VSI_TX_UNDERRUN)
                                {
                                        cf->can_id |= CAN_ERR_ACK;
                                }
                                else
                                {
                                        cf->can_id |= CAN_ERR_PROT | CAN_ERR_BUSERROR;
                                        cf->data[2] = CAN_ERR_PROT_TX;
                                }

                                stats->tx_errors++;
                        }
                        else
                        {
                                if (msg->StatusBitField & SPY_STATUS_BUS_SHORTED_PLUS)
                                {
                                        cf->can_id |= CAN_ERR_TRX | CAN_ERR_BUSERROR;
                                        cf->data[4] = CAN_ERR_TRX_CANH_SHORT_TO_BAT |
                                                        CAN_ERR_TRX_CANL_SHORT_TO_BAT;
                                }
                                else
                                {
                                        cf->can_id |= CAN_ERR_BUSERROR;
                                }

                                stats->rx_over_errors++;
                                stats->rx_errors++;
                        }
                }
                else
                {
                        if (msg->StatusBitField & SPY_STATUS_XTD_FRAME)
                                cf->can_id  |= (msg->ArbIDOrHeader & CAN_EFF_MASK)
                                                | CAN_EFF_FLAG;
                        else
                                cf->can_id  |= msg->ArbIDOrHeader & CAN_SFF_MASK;
                        if (msg->StatusBitField & SPY_STATUS_REMOTE_FRAME)
                                cf->can_id |= CAN_RTR_FLAG;

                        cf->can_dlc = get_can_dlc(msg->NumberBytesData);
                        memcpy(cf->data, msg->Data, cf->can_dlc);
                }

                /* pass along the converted message to the kernel for dispatch */
                ret = netif_rx(skb);
                WARN_ONCE(ret == NET_RX_DROP,
                        "intrepid: Dropping message on %s: backlog full\n", device->name);

                /* update our interface's stats */
                stats->rx_bytes += cf->can_dlc;
                stats->rx_packets++;
        }

        return 0;
}

static long intrepid_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
        int ret = -EINVAL;
        if (mutex_lock_interruptible(&ioctl_mutex)) {
                pr_info("intrepid: ioctl handler interrupted\n");
                return -ERESTARTSYS;
        }

        switch (cmd)
        {
        case SIOCSADDIF:
        {
                struct intrepid_netdevice *result = NULL;

                ret = intrepid_add_if(&result);
                if (result && (ret >= 0) && arg)
                {
                        int len = strlen(result->dev->name) + 1;
                        if (copy_to_user((void __user *)arg, result->dev->name, len))
                        {
                                intrepid_remove_if(ret);
                                ret = -EFAULT;
                                break;
                        }
                }
        }       break;
        case SIOCSREMOVEIF:
                ret = intrepid_remove_if(arg);
                break;
        case SIOCGSHAREDMEMSIZE:
                ret = SHARED_MEM_SIZE;
                break;
        case SIOCGMAXIFACES:
                ret = MAX_NET_DEVICES;
                break;
        case SIOCSMSGSWRITTEN:
        {
                int             index = (int)(arg >> 16);
                unsigned int    count = (int)(arg & 0xffff);

                ret = intrepid_read_messages(index, count);
        }
                break;
        } /* end switch (cmd) */

        mutex_unlock(&ioctl_mutex);
        return ret;
}

/* when the mmap()ed pages are first accesed by usermode there will be a page fault.
 * here we simply linerally map in the big vmalloc() we got */
static int intrepid_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
        vmf->page = vmalloc_to_page(shared_mem + (vmf->pgoff << PAGE_SHIFT));
        get_page(vmf->page); /* increment reference count, very important */

        return 0;
}

static struct vm_operations_struct intrepid_vm_ops = {
        .fault          = intrepid_vm_fault
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

        /* these are the ping pong buffers we'll use to transfer tx requests to usermode */
        tx_box_count[0] = 0;
        tx_box_count[1] = 0;

        /* the current tx box is shared across all devices */
        current_tx_box = 0;

        is_open = 1;

        return 0;
}

/* called when /dev/intrepid_netdevice is close -- delete any created interfaces */
static int intrepid_dev_release(struct inode *ip, struct file *fp)
{
        int i;

        if (!is_open)
                return -EIO;

        tx_box_count[0] = 0;
        tx_box_count[1] = 0;

        wake_up_interruptible(&tx_wait);

        for (i = 0 ; i < MAX_NET_DEVICES ; ++i)
        {
                if (net_devices[i] != NULL)
                        intrepid_remove_if(i);
        }

        is_open = 0;
        return 0;
}

/* usermode uses read() to get the current size of the tx buffer. we use a ping pong buffer
 * so the user doesn't have to worry about the data changing out from under them while
 * still avoiding a full copy to user. the ping pong flips on every call to this func */
static ssize_t intrepid_dev_read(struct file *fp, char *buffer, size_t len, loff_t *offset)
{
        struct intrepid_pending_tx_info info;
        struct net_device* dev;
        struct intrepid_netdevice *ics;
        int ret, i;

        if (len < sizeof(info))
                return -EFAULT;

        spin_lock_bh(&tx_box_lock);

        /* fill out the info for the user */
        info.tx_box_index = current_tx_box;
        info.count        = tx_box_count[current_tx_box];

        ret = copy_to_user(buffer, &info, sizeof(info));

        /* if we're full, pause the queue */
        if (info.count == MAX_NUM_TX_MSGS)
        {
                for(i = 0 ; i < MAX_NET_DEVICES ; ++i)
                {
                        dev = net_devices[i];
                        if (dev == NULL)
                                continue;

                        ics = netdev_priv(dev);

                        if (ics->is_stopped)
                        {
                                spin_lock_bh(&ics->lock);
                                netif_wake_queue(dev);
                                spin_unlock_bh(&ics->lock);
                        }
                }
        }

        tx_box_count[current_tx_box] = 0;

        /* swap to the other buffer. once we unlock new tx messages will go to the new box */
        if (current_tx_box == 0)
                current_tx_box = 1;
        else
                current_tx_box = 0;

        spin_unlock_bh(&tx_box_lock);

        if (ret != 0)
        {
                return -EFAULT;
        }

        return sizeof(info);
}

static unsigned int intrepid_dev_poll(struct file *fp, poll_table *wait)
{
        /* tx_wait is woken up in intrepid_netdevice_xmit. remember we're backwards here;
         * the usermode is waiting to read messages to subsequently transmit out */
        poll_wait(fp, &tx_wait, wait);

        if (tx_box_count[current_tx_box] > 0)
                return POLLIN | POLLRDNORM;

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

        is_open = 0;

        /* this is the shared memory used to transfer between us and the user daemon */
        shared_mem = vmalloc_user(SHARED_MEM_SIZE);
        if (!shared_mem)
        {
                ret = -ENOMEM;
                goto exit;
        }

        /* make space for up to MAX_NET_DEVICES devices */
        net_devices = kzalloc(sizeof(struct net_device*) * MAX_NET_DEVICES, GFP_KERNEL);
        if (!net_devices)
        {
                ret = -ENOMEM;
                goto free_shared_mem;
        }

        /* to make our ioctls blocking we wrap the handlers in a global mutex */
        mutex_init(&ioctl_mutex);

        /* this is the queue of processes waiting to read from our device. we'll signal
         * once some tx messages are ready */
        init_waitqueue_head(&tx_wait);

        /* this is used to arbitrate access to current_tx_box and tx_box_count */
        spin_lock_init(&tx_box_lock);

        /* parts of the shared memory for sending tx messages to user. we use ping pong
         * buffers that get switched whenever we handle a read() */
        tx_boxes[0]     = GET_TX_BOX(0);
        tx_boxes[1]     = GET_TX_BOX(1);

        /* create /dev/intrepid_netdevice */

        major_number = register_chrdev(0, INTREPID_DEVICE_NAME, &intrepid_fops);
        if (major_number < 0)
        {
                pr_alert("intrepid: failed to register major number, got %d\n",
                        major_number);
                return -1;
        }

        intrepid_dev_class = class_create(THIS_MODULE, INTREPID_CLASS_NAME);
        if (IS_ERR(intrepid_dev_class))
        {
                ret = PTR_ERR(intrepid_dev_class);
                pr_alert("intrepid: failed to create device class, got %d\n", ret);
                unregister_chrdev(major_number, INTREPID_DEVICE_NAME);
                goto free_net_devices;
        }

        intrepid_dev = device_create(intrepid_dev_class, NULL,
                MKDEV(major_number, 0), NULL, INTREPID_DEVICE_NAME);
        if(IS_ERR(intrepid_dev))
        {
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
        kzfree(net_devices);
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

        for (i = 0 ; i < MAX_NET_DEVICES ; ++i)
        {
                if (net_devices[i] != NULL)
                {
                        net_devices[i]->destructor = NULL; /* no dangling callbacks */
                        intrepid_remove_if(i);
                }
        }

        kfree(net_devices);
        net_devices = NULL;

        vfree(shared_mem);
        shared_mem = NULL;

}

module_init(intrepid_init);
module_exit(intrepid_exit);

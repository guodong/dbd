/**
1. send request via socket
2. make the thread in wait queue
3. once the response come, wake up wait queue
4. all thread check the sequence, if it isn't it's response, goto wait
 **/
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/hdreg.h>
#include <linux/sched.h>

#include <net/sock.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "defs.h"
#include "ucomm.h"

#define __GFP_MEMALLOC		0x2000u

#define VBD_MAX_PARTITION       4

#define VBD_SECTOR_SIZE         512
#define VBD_SECTORS                 16
#define VBD_HEADS                       4
#define VBD_CYLINDERS           256

#define VBD_SECTOR_TOTAL        (VBD_SECTORS * VBD_HEADS * VBD_CYLINDERS)
#define VBD_SIZE                        (VBD_SECTOR_SIZE * VBD_SECTOR_TOTAL)
#define DBD_MAGIC 0x68797548

struct dbd_device {
    spinlock_t queue_lock;
    wait_queue_head_t wq;
    struct gendisk *disk;
};

static struct dbd_device *dbd;

static int major;
static int exit = 0;
struct sock *nl_sk = NULL;

int is_create = 0;
pid_t client_pid;

struct list_head request_list;

static struct request *find_request(struct request *xreq) {
    struct request *req, *tmp;
    int err;

    list_for_each_entry_safe(req, tmp, &request_list, queuelist) {
        if (req != xreq)
            continue;
        list_del_init(&req->queuelist);
        return req;
    }

    err = -ENOENT;
    return ERR_PTR(err);
}

static int dbd_open(struct block_device *bdev, fmode_t mode) {
    return 0;
}

static int dbd_release(struct gendisk *gd, fmode_t mode) {
    return 0;
}

static int dbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg) {
    int err;
    struct hd_geometry geo;
    switch (cmd) {
        case HDIO_GETGEO:
            err = !access_ok(VERIFY_WRITE, arg, sizeof (geo));
            if (err) return -EFAULT;

            geo.cylinders = VBD_CYLINDERS;
            geo.heads = VBD_HEADS;
            geo.sectors = VBD_SECTORS;
            geo.start = get_start_sect(bdev);
            if (copy_to_user((void*) arg, &geo, sizeof (geo)))
                return -EFAULT;
            return 0;
    }
    return -ENOTTY;
}

int sendnlmsg(void *message, int length) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(length);

    if (!message || !nl_sk) {
        return -1;
    }

    // Allocate a new sk_buffer   
    skb = alloc_skb(len, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "my_net_link: alloc_skb Error./n");
        return -1;
    }

    //Initialize the header of netlink message   
    nlh = nlmsg_put(skb, 0, 0, 0, length, 0);

    NETLINK_CB(skb).pid = 0; // from kernel   
    NETLINK_CB(skb).dst_group = 0; // multi cast   

    memcpy(NLMSG_DATA(nlh), message, length);
    //printk("my_net_link: send message '%s'./n", (char *) NLMSG_DATA(nlh));

    //send message by multi cast   
    //return netlink_broadcast(nl_sk, skb, 0, 1, GFP_KERNEL);
    return netlink_unicast(nl_sk, skb, client_pid, 0);
}

static inline int sock_recv_bvec(struct bio_vec *bvec, char *buf) {
    int result = 0;
    void *kaddr = kmap(bvec->bv_page);
    memcpy(kaddr + bvec->bv_offset, buf, bvec->bv_len);
    //    result = sock_xmit(sock, 0, kaddr + bvec->bv_offset, bvec->bv_len,
    //            MSG_WAITALL);
    kunmap(bvec->bv_page);
    return result;
}

static inline int sock_send_bvec(struct bio_vec *bvec, char *buf) {
    int result = 0;
    void *kaddr = kmap(bvec->bv_page);
    memcpy(buf, kaddr + bvec->bv_offset, bvec->bv_len);
    //    result = sock_xmit(sock, 1, kaddr + bvec->bv_offset,
    //            bvec->bv_len, flags);
    kunmap(bvec->bv_page);
    return result;
}

void dbd_req_func(struct request_queue *q) {
    struct request *req;
    struct dbd_local_request dbd_rqst;

    while ((req = blk_fetch_request(q)) != NULL) {
        dbd_rqst.domain = 0;
        dbd_rqst.cmd = (rq_data_dir(req) == READ) ? DBD_CMD_IO_READ : DBD_CMD_IO_WRITE;
        dbd_rqst.addr = blk_rq_pos(req)*512;
        dbd_rqst.size = blk_rq_bytes(req);
        memcpy(dbd_rqst.handle, &req, sizeof (req));
        sendnlmsg(&dbd_rqst, sizeof (dbd_rqst));

        if (dbd_rqst.cmd == DBD_CMD_IO_WRITE) {
            /**
             * @notice here can not use char buf[dbd_rqst.size], because size is long type not int type
             */
            char *buf = vmalloc(dbd_rqst.size);
            char *p = buf;
            struct req_iterator iter;
            struct bio_vec *bv;
            char *buffer;
            //
            printk("\n");

            rq_for_each_segment(bv, req, iter) { /*get each bio from request */
                buffer = page_address(bv->bv_page) + bv->bv_offset;
                memcpy(p, buffer, bv->bv_len);
                p += bv->bv_len;
            }
            
            sendnlmsg(buf, dbd_rqst.size);
            vfree(buf);
        }
        printk("send type %d addr: %ld\n", dbd_rqst.cmd, dbd_rqst.addr);
        list_add(&req->queuelist, &request_list);
        //__blk_end_request_all(req, 0);
    }

}

static struct block_device_operations dbd_fops = {
    .owner = THIS_MODULE,
    .open = dbd_open,
    .release = dbd_release,
    .ioctl = dbd_ioctl,
};

int dbd_create(void) {
    major = register_blkdev(0, "dbd");
    dbd->disk = alloc_disk(4);
    spin_lock_init(&dbd->queue_lock);
    dbd->disk->queue = blk_init_queue(dbd_req_func, &dbd->queue_lock);
    dbd->disk->major = major;
    dbd->disk->first_minor = 1;
    dbd->disk->private_data = dbd;
    dbd->disk->fops = &dbd_fops;
    sprintf(dbd->disk->disk_name, "dbd");
    set_capacity(dbd->disk, 10240 / 5 * 16);
    add_disk(dbd->disk);
    return 0;
}

void dbd_remove(char *name) {
    blk_cleanup_queue(dbd->disk->queue);
    del_gendisk(dbd->disk);
    put_disk(dbd->disk);
    unregister_blkdev(major, name);
}

void nl_recv_thread(struct sk_buff *__skb) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct dbd_local_msg *msg;
    struct request *req;

    skb = skb_get(__skb);
    if (skb->len < NLMSG_SPACE(0)) {
        goto free;
    }
    nlh = (struct nlmsghdr *) skb->data;
    msg = NLMSG_DATA(nlh);

    switch (msg->type) {
        case DBD_LOCAL_MSG_REQUEST:
            switch (msg->request.cmd) {
                case DBD_CMD_CTRL_CREATE:
                    client_pid = nlh->nlmsg_pid;
                    dbd_create();
                    is_create = 1;
                    break;
                default:
                    break;
            }
            break;
        case DBD_LOCAL_MSG_RESPONSE:
        {
            printk("get response\n");
            req = find_request(*(struct request **) msg->response.handle);
            if (rq_data_dir(req) == READ) {
                struct req_iterator iter;
                struct bio_vec *bvec;
                char *buf, *p;
                int s = blk_rq_bytes(req);
                printk("%d %d\n\n", s, blk_rq_bytes(req));
                buf = (char*) vmalloc(s);
                memcpy(buf, NLMSG_DATA(nlh) + sizeof (*msg), s);
                p = buf;

                //memcpy(req->buffer, buf, s);

                rq_for_each_segment(bvec, req, iter) {
                    void *kaddr = kmap(bvec->bv_page);
                    memcpy(kaddr + bvec->bv_offset, p, bvec->bv_len);
                    //printk("request %p: got %d bytes data\n", req, bvec->bv_len);
                    kunmap(bvec->bv_page);
                    p += bvec->bv_len;
                }
                vfree(buf);
                //memcpy(req->buffer, NLMSG_DATA(nlh + nlh->nlmsg_len), blk_rq_bytes(req));
            }
            __blk_end_request_all(req, 0);
            break;
        }
        default:
            break;
    }
free:
    kfree_skb(skb);
}

static int __init dbd_init(void) {
    INIT_LIST_HEAD(&request_list);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_PROTOCAL, 0, nl_recv_thread, NULL, THIS_MODULE);
    if (!nl_sk) {
        printk("netlink:can not create");
    }
    dbd = kcalloc(1, sizeof (*dbd), GFP_KERNEL);
    printk("init\n");
    //dbd_create();
    return 0;
}

static void __exit dbd_exit(void) {
    exit = 1;
    if (is_create) dbd_remove("dbd");
    kfree(dbd);
    netlink_kernel_release(nl_sk);
}

module_init(dbd_init);
module_exit(dbd_exit);
MODULE_LICENSE("GPL");

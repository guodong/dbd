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

#include "comm.h"

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
    struct list_head sending_list; /* Requests waiting result */
    struct list_head waiting_list; /* Requests to be sent */
    wait_queue_head_t send_wq;
    wait_queue_head_t recv_wq;
    struct gendisk *disk;
};

static struct dbd_device *dbd;

static struct socket *sk;
static struct task_struct *send_thread;
static struct task_struct *recv_thread;

static int major;
static int exit = 0;

struct socket *sock_conn(const char *ip, int port) {
    struct socket *sock = NULL;
    struct sockaddr_in dest;
    memset(&dest, '\0', sizeof (dest));
    sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = in_aton(ip);
    dest.sin_port = htons(port);
    sock->ops->connect(sock, (struct sockaddr*) &dest, sizeof (struct sockaddr_in), !O_NONBLOCK);
    return sock;
}



static int sock_xmit(int send, void *buf, int size,
        int msg_flags) {
    struct socket *sock = sk;
    int result;
    struct msghdr msg;
    struct kvec iov;
    sigset_t blocked, oldset;
    //unsigned long pflags = current->flags;



    /* Allow interception of SIGKILL only
     * Don't allow other signals to interrupt the transmission */
    siginitsetinv(&blocked, sigmask(SIGKILL));
    sigprocmask(SIG_SETMASK, &blocked, &oldset);

    current->flags |= PF_MEMALLOC;
    do {
        sock->sk->sk_allocation = GFP_NOIO | __GFP_MEMALLOC;
        iov.iov_base = buf;
        iov.iov_len = size;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = msg_flags | MSG_NOSIGNAL;

        if (send) {
            //struct timer_list ti;

            //			if (nbd->xmit_timeout) {
            //				init_timer(&ti);
            //				ti.function = nbd_xmit_timeout;
            //				ti.data = (unsigned long)current;
            //				ti.expires = jiffies + nbd->xmit_timeout;
            //				add_timer(&ti);
            //			}
            result = kernel_sendmsg(sock, &msg, &iov, 1, size);
            //			if (nbd->xmit_timeout)
            //				del_timer_sync(&ti);
        } else
            result = kernel_recvmsg(sock, &msg, &iov, 1, size,
                msg.msg_flags);

        if (signal_pending(current)) {
            siginfo_t info;
            printk(KERN_WARNING "nbd (pid %d: %s) got signal %d\n",
                    task_pid_nr(current), current->comm,
                    dequeue_signal_lock(current, &current->blocked, &info));
            result = -EINTR;
            //sock_shutdown(nbd, !send);
            break;
        }

        if (result <= 0) {
            if (result == 0)
                result = -EPIPE; /* short read */
            break;
        }
        size -= result;
        buf += result;
    } while (size > 0);

    sigprocmask(SIG_SETMASK, &oldset, NULL);
    //tsk_restore_flags(current, pflags, PF_MEMALLOC);

    return result;
}

static inline int sock_send_bvec(struct bio_vec *bvec,
        int flags) {
    int result;
    void *kaddr = kmap(bvec->bv_page);
    result = sock_xmit(1, kaddr + bvec->bv_offset,
            bvec->bv_len, flags);
    kunmap(bvec->bv_page);
    return result;
}

static inline int sock_recv_bvec(struct bio_vec *bvec) {
    int result;
    void *kaddr = kmap(bvec->bv_page);
    result = sock_xmit(0, kaddr + bvec->bv_offset, bvec->bv_len,
            MSG_WAITALL);
    kunmap(bvec->bv_page);
    return result;
}

static struct request *find_request(struct request *xreq) {
    struct request *req, *tmp;
    int err;

    list_for_each_entry_safe(req, tmp, &dbd->waiting_list, queuelist) {
        if (req != xreq)
            continue;
        list_del_init(&req->queuelist);
        return req;
    }

    err = -ENOENT;
    return ERR_PTR(err);
}



static int dbd_send_thread(void *data) {
    struct request *req;
    struct dbd_request dbd_rqst;
    int flags = 0;

    while (!kthread_should_stop()) {
        wait_event_interruptible(dbd->send_wq, kthread_should_stop() || !list_empty(&dbd->sending_list));
        if(exit) break;
        req = list_entry(dbd->sending_list.next, struct request, queuelist);
        list_del_init(&req->queuelist);
        dbd_rqst.dbd_cmd = (rq_data_dir(req) == READ) ? DBD_CMD_READ : DBD_CMD_WRITE;
        dbd_rqst.addr = blk_rq_pos(req)*512;
        dbd_rqst.size = blk_rq_bytes(req);
        memcpy(dbd_rqst.handle, &req, sizeof (req));
        sock_xmit(1, &dbd_rqst, sizeof (dbd_rqst), (dbd_rqst.dbd_cmd == DBD_CMD_WRITE) ? MSG_MORE : 0);

        if (dbd_rqst.dbd_cmd == DBD_CMD_WRITE) {
            struct req_iterator iter;
            struct bio_vec *bvec;

            rq_for_each_segment(bvec, req, iter) {
                flags = 0;
                if (!rq_iter_last(req, iter))
                    flags = MSG_MORE;
                printk("request %p: sending %d bytes data\n", req, bvec->bv_len);
                sock_send_bvec(bvec, flags);
            }
        }
        list_add_tail(&req->queuelist, &dbd->waiting_list);
        wake_up(&dbd->recv_wq);
    }
    return 0;
}

static int dbd_recv_thread(void *data) {
    struct dbd_response dbd_rsps;
    struct request *req;

    while (!kthread_should_stop()) {
        wait_event_interruptible(dbd->recv_wq, kthread_should_stop() || !list_empty(&dbd->waiting_list));
        if(exit) break;
        sock_xmit(0, &dbd_rsps, sizeof (dbd_rsps), MSG_WAITALL);
        req = find_request(*(struct request **) dbd_rsps.handle);
        if (dbd_rsps.dbd_cmd == DBD_CMD_READ) {
            struct req_iterator iter;
            struct bio_vec *bvec;

            rq_for_each_segment(bvec, req, iter) {
                sock_recv_bvec(bvec);
                printk("request %p: got %d bytes data\n", req, bvec->bv_len);
            }
        }
        list_del_init(&req->queuelist);
        __blk_end_request_all(req, 0);
    }
    return 0;
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

void dbd_req_func(struct request_queue *q) {
    struct request *req;
    while ((req = blk_fetch_request(q)) != NULL) {
        printk("request %p: sending control (%d@%llu,%uB)\n",
                req,
                rq_data_dir(req),
                (unsigned long long) blk_rq_pos(req) << 9,
                blk_rq_bytes(req));
        list_add_tail(&req->queuelist, &dbd->sending_list);
        wake_up(&dbd->send_wq);
    }

}

void run_thread(void) {
    init_waitqueue_head(&dbd->send_wq);
    init_waitqueue_head(&dbd->recv_wq);
    send_thread = kthread_create(dbd_send_thread, NULL, "dbd_send");
    wake_up_process(send_thread);
    recv_thread = kthread_create(dbd_recv_thread, NULL, "dbd_recv");
    wake_up_process(recv_thread);
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
    set_capacity(dbd->disk, 10240);
    add_disk(dbd->disk);
    return 0;
}

void dbd_remove(char *name) {
    blk_cleanup_queue(dbd->disk->queue);
    del_gendisk(dbd->disk);
    put_disk(dbd->disk);
    unregister_blkdev(major, "dbd");
}

static int __init dbd_init(void) {
    dbd = kcalloc(1, sizeof (*dbd), GFP_KERNEL);
    INIT_LIST_HEAD(&dbd->sending_list);
    INIT_LIST_HEAD(&dbd->waiting_list);
    sk = sock_conn("0.0.0.0", 8888);
    run_thread();
    dbd_create();
    return 0;
}

static void __exit dbd_exit(void) {
    exit = 1;
    dbd_remove("dbd");    
    kthread_stop(send_thread);    
    kthread_stop(recv_thread);
    wake_up(&dbd->send_wq);
    wake_up(&dbd->recv_wq);
    sock_release(sk);
    kfree(dbd);
}

module_init(dbd_init);
module_exit(dbd_exit);
MODULE_LICENSE("GPL");

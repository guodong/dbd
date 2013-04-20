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

//static unsigned int debugflags;
#define err(msg) printk(KERN_INFO "%s failed.\n", msg)
#define dprintk(flags, fmt...) do { \
	if (debugflags & (flags)) printk(KERN_DEBUG fmt); \
} while (0)
#define __GFP_MEMALLOC		0x2000u

#define VBD_MAX_PARTITION       4

#define VBD_SECTOR_SIZE         512
#define VBD_SECTORS                 16
#define VBD_HEADS                       4
#define VBD_CYLINDERS           256

#define VBD_SECTOR_TOTAL        (VBD_SECTORS * VBD_HEADS * VBD_CYLINDERS)
#define VBD_SIZE                        (VBD_SECTOR_SIZE * VBD_SECTOR_TOTAL)
#define DBD_MAGIC 0x68797548



#define dbd_cmd(req) ((req)->cmd[0])
#define NBD_REQUEST_MAGIC 0x25609513
#define NBD_REPLY_MAGIC 0x67446698

struct dbd_device {
    int flags;
    int harderror; /* Code of hard error			*/
    struct socket * sock;
    struct file * file; /* If == NULL, device is not ready, yet	*/
    int magic;

    spinlock_t queue_lock;
    struct list_head queue_head; /* Requests waiting result */
    struct request *active_req;
    wait_queue_head_t active_wq;
    struct list_head waiting_queue; /* Requests to be sent */
    wait_queue_head_t waiting_wq;

    struct mutex tx_lock;
    struct gendisk *disk;
    int blksize;
    u64 bytesize;
    pid_t pid; /* pid of nbd-client, if attached */
    int xmit_timeout;
};

static struct dbd_device *dbd_dev;
static dev_t major;
static DEFINE_SPINLOCK(dbd_lock);

static struct socket *sk;
//static struct list_head waiting_queue;
//static struct task_struct *thread;
//static wait_queue_head_t wq;
//static int has_req = 0;
//static int exit = 0;



static void dbd_end_request(struct request *req) {
    int error = req->errors ? -EIO : 0;
    struct request_queue *q = req->q;
    unsigned long flags;

    spin_lock_irqsave(q->queue_lock, flags);
    __blk_end_request_all(req, error);
    spin_unlock_irqrestore(q->queue_lock, flags);
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

static int dbd_send_req(struct request *req) {
    int result, flags;
    struct dbd_request request;
    unsigned long size = blk_rq_bytes(req);

    request.magic = htonl(NBD_REQUEST_MAGIC);
    request.type = htonl(dbd_cmd(req));
    request.from = cpu_to_be64((u64) blk_rq_pos(req) << 9);
    request.len = htonl(size);
    memcpy(request.handle, &req, sizeof (req));

    result = sock_xmit(1, &request, sizeof (request),
            (dbd_cmd(req) == NBD_CMD_WRITE) ? MSG_MORE : 0);
    if (result <= 0) {
        dev_err(disk_to_dev(dbd_dev->disk),
                "Send control failed (result %d)\n", result);
        goto error_out;
    }

    if (dbd_cmd(req) == NBD_CMD_WRITE) {
        struct req_iterator iter;
        struct bio_vec *bvec;

        /*
         * we are really probing at internals to determine
         * whether to set MSG_MORE or not...
         */
        rq_for_each_segment(bvec, req, iter) {
            flags = 0;
            if (!rq_iter_last(req, iter))
                flags = MSG_MORE;
            result = sock_send_bvec(bvec, flags);
            if (result <= 0) {
                dev_err(disk_to_dev(dbd_dev->disk),
                        "Send data failed (result %d)\n",
                        result);
                goto error_out;
            }
        }
    }
    return 0;

error_out:
    return -EIO;
}

static void dbd_handle_req(struct request *req) {
    if (req->cmd_type != REQ_TYPE_FS)
        goto error_out;

    dbd_cmd(req) = NBD_CMD_READ;
    if (rq_data_dir(req) == WRITE) {
        dbd_cmd(req) = NBD_CMD_WRITE;
    }

    req->errors = 0;

    mutex_lock(&dbd_dev->tx_lock);

    dbd_dev->active_req = req;

    if (dbd_send_req(req) != 0) {
        dev_err(disk_to_dev(dbd_dev->disk), "Request send failed\n");
        req->errors++;
        dbd_end_request(req);
    } else {
        spin_lock(&dbd_dev->queue_lock);
        list_add_tail(&req->queuelist, &dbd_dev->queue_head);
        spin_unlock(&dbd_dev->queue_lock);
    }

    dbd_dev->active_req = NULL;
    mutex_unlock(&dbd_dev->tx_lock);
    wake_up_all(&dbd_dev->active_wq);

    return;

error_out:
    req->errors++;
    dbd_end_request(req);
}

static int dbd_thread(void *data) {
    struct dbd_device *nbd = dbd_dev;
    struct request *req;

    set_user_nice(current, -20);
    while (!kthread_should_stop() || !list_empty(&nbd->waiting_queue)) {
        /* wait for something to do */
        wait_event_interruptible(nbd->waiting_wq, 
                //kthread_should_stop() ||
                !list_empty(&nbd->waiting_queue));

        /* extract request */
        if (list_empty(&nbd->waiting_queue))
            continue;

        spin_lock_irq(&nbd->queue_lock);
        req = list_entry(nbd->waiting_queue.next, struct request,
                queuelist);
        list_del_init(&req->queuelist);
        spin_unlock_irq(&nbd->queue_lock);

        /* handle request */
        dbd_handle_req(req);
    }
    return 0;
}

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
        struct dbd_device *nbd;

    while ((req = blk_fetch_request(q)) != NULL) {
        printk("request %p: sending control (%d@%llu,%uB)\n",
			req,
			dbd_cmd(req),
			(unsigned long long)blk_rq_pos(req) << 9,
			blk_rq_bytes(req));

        spin_unlock_irq(q->queue_lock);

        nbd = req->rq_disk->private_data;

        spin_lock_irq(&nbd->queue_lock);
        list_add_tail(&req->queuelist, &nbd->waiting_queue);
        spin_unlock_irq(&nbd->queue_lock);

        wake_up(&dbd_dev->waiting_wq);

        spin_lock_irq(q->queue_lock);/**/
        //__blk_end_request_all(req, 0);
    }

}
static struct block_device_operations dbd_fops = {
    .owner = THIS_MODULE,
    .open = dbd_open,
    .release = dbd_release,
    .ioctl = dbd_ioctl,
};

static struct request *dbd_find_request(struct request *xreq) {
    struct request *req, *tmp;
    int err;
    struct dbd_device *nbd = dbd_dev;

    //err = wait_event_interruptible(nbd->active_wq, nbd->active_req != xreq);

    spin_lock(&nbd->queue_lock);

    list_for_each_entry_safe(req, tmp, &nbd->queue_head, queuelist) {
        if (req != xreq)
            continue;
        list_del_init(&req->queuelist);
        spin_unlock(&nbd->queue_lock);
        return req;
    }
    spin_unlock(&nbd->queue_lock);

    err = -ENOENT;
    return ERR_PTR(err);
}

static struct request *dbd_read_stat(void) {
    struct dbd_device *nbd = dbd_dev;
    int result;
    struct dbd_reply reply;
    struct request *req;

    reply.magic = 0;
    result = sock_xmit(0, &reply, sizeof (reply), MSG_WAITALL);
    if (result <= 0) {
        dev_err(disk_to_dev(nbd->disk),
                "Receive control failed (result %d)\n", result);
        goto harderror;
    }

    req = dbd_find_request(*(struct request **) reply.handle);
    if (IS_ERR(req)) {
        result = PTR_ERR(req);
        if (result != -ENOENT)
            goto harderror;

        dev_err(disk_to_dev(nbd->disk), "Unexpected reply (%p)\n",
                reply.handle);
        result = -EBADR;
        goto harderror;
    }

    //dprintk("%s: request %p: got reply\n",
    //        nbd->disk->disk_name, req);
    if (dbd_cmd(req) == NBD_CMD_READ) {
        struct req_iterator iter;
        struct bio_vec *bvec;

        rq_for_each_segment(bvec, req, iter) {
            result = sock_recv_bvec(bvec);
            if (result <= 0) {
                dev_err(disk_to_dev(nbd->disk), "Receive data failed (result %d)\n",
                        result);
                req->errors++;
                return req;
            }
            //dprintk(DBG_RX, "%s: request %p: got %d bytes data\n",
             //       nbd->disk->disk_name, req, bvec->bv_len);
        }
    }
    return req;
harderror:
    nbd->harderror = result;
    return NULL;
}

int dbd_main(void) {
    struct request *req;

    while ((req = dbd_read_stat()) != NULL)
        dbd_end_request(req);

    dbd_dev->pid = 0;
    return 0;
}

static void dbd_clear_que(void) {
    struct request *req;

    while (!list_empty(&dbd_dev->queue_head)) {
        req = list_entry(dbd_dev->queue_head.next, struct request,
                queuelist);
        list_del_init(&req->queuelist);
        req->errors++;
        dbd_end_request(req);
    }

    while (!list_empty(&dbd_dev->waiting_queue)) {
        req = list_entry(dbd_dev->waiting_queue.next, struct request,
                queuelist);
        list_del_init(&req->queuelist);
        req->errors++;
        dbd_end_request(req);
    }
}

int dbd_do_it(void) {

    struct dbd_device *dbd = dbd_dev;

    struct task_struct *thread;
    int error;

    mutex_unlock(&dbd_dev->tx_lock);

    thread = kthread_create(dbd_thread, NULL, "ggg");
    if (IS_ERR(thread)) {
        mutex_lock(&dbd->tx_lock);
        return PTR_ERR(thread);
    }
    wake_up_process(thread);
    error = dbd_main();
    kthread_stop(thread);

    mutex_lock(&dbd->tx_lock);
    if (error)
        return error;
    sock_release(sk);
    dbd_clear_que();
    dev_warn(disk_to_dev(dbd->disk), "queue cleared\n");
    queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, dbd->disk->queue);
    dbd->bytesize = 0;
    return dbd->harderror;
}

int dbd_create(void) {
    int err = -ENOMEM;
    int major;
    int part_shift;
    struct gendisk *disk;

    dbd_dev = kcalloc(1, sizeof (*dbd_dev), GFP_KERNEL);
    if (!dbd_dev)
        return -ENOMEM;

    part_shift = 0;

    disk = alloc_disk(4);
    if (!disk)
        goto out;
    dbd_dev->disk = disk;
    disk->queue = blk_init_queue(dbd_req_func, &dbd_lock);
    if (!disk->queue) {
        put_disk(disk);
        goto out;
    }
    /*
     * Tell the block layer that we are not a rotational device
     */
    queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
    disk->queue->limits.discard_granularity = 512;
    disk->queue->limits.max_discard_sectors = UINT_MAX;
    disk->queue->limits.discard_zeroes_data = 0;

    major = register_blkdev(0, "dbd");
    if (!major) {
        err = -EIO;
        goto out;
    }

    printk(KERN_INFO "dbd: registered device at major %d\n", major);

    dbd_dev->file = NULL;
    dbd_dev->magic = DBD_MAGIC;
    dbd_dev->flags = 0;
    INIT_LIST_HEAD(&dbd_dev->waiting_queue);
    spin_lock_init(&dbd_dev->queue_lock);
    INIT_LIST_HEAD(&dbd_dev->queue_head);
    mutex_init(&dbd_dev->tx_lock);
    init_waitqueue_head(&dbd_dev->active_wq);
    init_waitqueue_head(&dbd_dev->waiting_wq);
    dbd_dev->blksize = 1024;
    dbd_dev->bytesize = 0;
    disk->major = major;
    disk->first_minor = 1;
    disk->fops = &dbd_fops;
    disk->private_data = &dbd_dev;
    sprintf(disk->disk_name, "dbd");
    set_capacity(disk, 10240);
    add_disk(disk);


    return 0;
out:
    blk_cleanup_queue(dbd_dev->disk->queue);
    put_disk(dbd_dev->disk);
    kfree(dbd_dev);
    return err;
}

void dbd_remove(char *name) {
    blk_cleanup_queue(dbd_dev->disk->queue);
    del_gendisk(dbd_dev->disk);
    put_disk(dbd_dev->disk);
    unregister_blkdev(major, name);
    kfree(dbd_dev);
}

static int __init dbd_init(void) {
    sk = sock_conn("192.168.1.102", 8888);
    dbd_create();
    dbd_do_it();
    return 0;
}

static void __exit dbd_exit(void) {
    dbd_remove("dbd");
    sock_release(sk);
}

module_init(dbd_init);
module_exit(dbd_exit);
MODULE_LICENSE("GPL");

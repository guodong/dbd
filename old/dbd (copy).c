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

#include <net/sock.h>
#include <linux/inet.h>
#include <linux/socket.h>

#include "comm.h"

#define err(msg) printk(KERN_INFO "%s failed.\n", msg)
#define __GFP_MEMALLOC		0x2000u

#define VBD_MAX_PARTITION       4

#define VBD_SECTOR_SIZE         512
#define VBD_SECTORS                 16
#define VBD_HEADS                       4
#define VBD_CYLINDERS           256

#define VBD_SECTOR_TOTAL        (VBD_SECTORS * VBD_HEADS * VBD_CYLINDERS)
#define VBD_SIZE                        (VBD_SECTOR_SIZE * VBD_SECTOR_TOTAL)

struct dbd_device
{
    struct gendisk *disk;
    spinlock_t lock;
    //struct list_head req_queue;
    struct request_queue *queue;
    int mt_lock;
    struct socket *sk;
};

static struct dbd_device *dev;
static dev_t major;

static struct socket *sk;
static int seq = 0;
static struct list_head waiting_queue;
static struct task_struct *thread;
static wait_queue_head_t wq;
static int has_req = 0;
static int exit = 0;

static struct request *find_request(struct request *xreq)
{
    struct request *req, *tmp;
    list_for_each_entry_safe(req, tmp, &waiting_queue, queuelist)
    {
        if(req != xreq)
            continue;
        list_del_init(&req->queuelist);
        return req;
    }
    return req;
}

static int sock_xmit(int send, void *buf, int size,
                     int msg_flags)
{
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
    do
    {
        sock->sk->sk_allocation = GFP_NOIO | __GFP_MEMALLOC;
        iov.iov_base = buf;
        iov.iov_len = size;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = msg_flags | MSG_NOSIGNAL;

        if (send)
        {
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
        }
        else
            result = kernel_recvmsg(sock, &msg, &iov, 1, size,
                                    msg.msg_flags);

        if (signal_pending(current))
        {
            siginfo_t info;
            printk(KERN_WARNING "nbd (pid %d: %s) got signal %d\n",
                   task_pid_nr(current), current->comm,
                   dequeue_signal_lock(current, &current->blocked, &info));
            result = -EINTR;
            //sock_shutdown(nbd, !send);
            break;
        }

        if (result <= 0)
        {
            if (result == 0)
                result = -EPIPE; /* short read */
            break;
        }
        size -= result;
        buf += result;
    }
    while (size > 0);

    sigprocmask(SIG_SETMASK, &oldset, NULL);
    //tsk_restore_flags(current, pflags, PF_MEMALLOC);

    return result;
}

static int dbd_thread(void *data)
{
    struct request *req;
    struct dbd_response rep;
    unsigned long s;
    char *buf;

    while( !kthread_should_stop())
    {
        if(list_empty(&waiting_queue))
        {
            has_req = 0;
            wait_event_interruptible(wq, has_req);
        }
        if(exit)
        {
            while(1)
            {
                if(kthread_should_stop())
                    return 0;
            }
        }
        sock_xmit(0, &rep, sizeof(rep), MSG_WAITALL);
        req = find_request(*(struct request **)rep.handle);
        if(rep.dbd_cmd == DBD_CMD_READ){
            s = blk_rq_cur_bytes(req);
            printk("%ld\n", s);
            buf = vmalloc(s);
            sock_xmit(0, buf, s, MSG_WAITALL);
            memcpy(req->buffer, buf, s);
            vfree(buf);
        }
        __blk_end_request_all(req, 0);
    }
    return 0;
}

struct socket *sock_conn(const char *ip, int port)
{
    struct socket *sock = NULL;
    struct sockaddr_in dest;
    memset(&dest, '\0', sizeof(dest));
    sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = in_aton(ip);
    dest.sin_port = htons(port);
    sock->ops->connect(sock, (struct sockaddr*)&dest, sizeof(struct sockaddr_in), !O_NONBLOCK);
    return sock;
}


static int dbd_open(struct block_device *bdev, fmode_t mode)
{
    return 0;
}

static int dbd_release(struct gendisk *gd, fmode_t mode)
{
    return 0;
}

static int dbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
    int err;
	struct hd_geometry geo;
	switch(cmd)
	{
		case HDIO_GETGEO:
			err = !access_ok(VERIFY_WRITE, arg, sizeof(geo));
			if(err) return -EFAULT;

			geo.cylinders = VBD_CYLINDERS;
			geo.heads = VBD_HEADS;
			geo.sectors = VBD_SECTORS;
			geo.start = get_start_sect(bdev);
			if(copy_to_user((void*)arg, &geo, sizeof(geo)))
				return -EFAULT;
			return 0;
	}
	return -ENOTTY;
}


// !!!!!
//int *make_tuple_id(unsigned long start, unsigned long size)
//{
//    struct request_tuples *req_tp;
//    req_tp = kmalloc(sizeof(request_tuples), GFP_KERNEL);
//    req_tp->first_tuple_id = start / TUPLE_SIZE;
//    int num = 1;
//    while(size > TUPLE_SIZE){
//        num += 1;
//        size -= TUPLE_SIZE;
//    }
//    req_tp->number = num;
//    return req_tp;
//}

void dbd_req_func(struct request_queue *q)
{
    struct request *req;
    unsigned long size = 0, start, s;
    struct dbd_request rq;
    char *b;

    //while((req = blk_fetch_request(q)) != NULL)
    req = blk_fetch_request(q);
    while(req)
    {
        start = blk_rq_pos(req)*512;
        size = blk_rq_cur_bytes(req);
        printk("send req %ld %ld\n", start, size);
        rq.seq = seq++;
        memcpy(rq.handle, &req, sizeof(req));
            list_add_tail(&req->queuelist, &waiting_queue);

            has_req = 1;
            wake_up(&wq);
        if(rq_data_dir(req) == READ)
        {
            rq.dbd_cmd = DBD_CMD_READ;

            rq.tuple_id = 0;
            rq.addr = start;
            rq.size = size;
            rq.length = sizeof(rq);
            sock_xmit(1, &rq, sizeof(rq), MSG_WAITALL);
        }
        else
        {
            rq.dbd_cmd = DBD_CMD_WRITE;
            rq.addr = start;
            rq.size = size;
            rq.length = sizeof(rq);
            s = size + sizeof(rq);
            b = vmalloc(s);
            memcpy(b, &rq, sizeof(rq));
            memcpy(&b[sizeof(rq)], req->buffer, size);
            sock_xmit(1, b, s, MSG_WAITALL);
            //
            //memcpy(b, req->buffer, size);
            //sock_xmit(1, req->buffer, size, MSG_WAITALL);
            vfree(b);
        }
        //while(dev->mt_lock){
        //    wait_event_interruptible(dev->waiting_queue, dev->mt_lock);
        //}
        //if(!__blk_end_request_cur(req, 0))
        req = blk_fetch_request(q);

    }
}
static struct block_device_operations dbd_fops =
{
    .owner = THIS_MODULE,
    .open = dbd_open,
    .release = dbd_release,
    .ioctl = dbd_ioctl,
};

int dbd_create(char *name, int size)
{
    sk = sock_conn("0.0.0.0", 8888);
    thread = kthread_create(dbd_thread, NULL, "ggg");
    wake_up_process(thread);

    init_waitqueue_head(&wq);

    major = register_blkdev(0, name);
    dev = kcalloc(1, sizeof(dev), GFP_KERNEL);
    dev->disk = alloc_disk(VBD_MAX_PARTITION);
    spin_lock_init(&dev->lock);
    dev->queue = blk_init_queue(dbd_req_func, &dev->lock);
    dev->disk->major = major;
    dev->disk->first_minor = 1;
    dev->disk->private_data = dev;
    dev->disk->fops = &dbd_fops;
    dev->disk->queue = dev->queue;
    sprintf(dev->disk->disk_name, name);
    set_capacity(dev->disk, size);

    INIT_LIST_HEAD(&waiting_queue);


    add_disk(dev->disk);
    return 0;
}

void dbd_remove(char *name)
{
    del_gendisk(dev->disk);
    put_disk(dev->disk);
    unregister_blkdev(major, name);
}

static int __init dbd_init(void)
{
    unsigned long long int t = 10240;//1024*64;
    printk("123");
    dbd_create("testb", t);
    return 0;
}

static void __exit dbd_exit(void)
{
    printk("1\n");
    has_req = 1;
    exit = 1;
    wake_up(&wq);
    kthread_stop(thread);
    printk("2\n");
    dbd_remove("testb");
    printk("3\n");
    sock_release(sk);
}

module_init(dbd_init);
module_exit(dbd_exit);
MODULE_LICENSE("GPL");

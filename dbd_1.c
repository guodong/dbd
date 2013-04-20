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
#include "list.h"

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
    struct gendisk *disk;
};

static struct dbd_device *dbd;

static int major;
static int exit = 0;
static struct farm *dbd_farm;

struct socket *sock_conn(const int ip, int port) {
    struct socket *sock = NULL;
    struct sockaddr_in dest;
    memset(&dest, '\0', sizeof (dest));
    sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip;
    dest.sin_port = htons(port);
    sock->ops->connect(sock, (struct sockaddr*) &dest, sizeof (struct sockaddr_in), !O_NONBLOCK);
    return sock;
}



static int sock_xmit(struct socket *sock, int send, void *buf, int size,
        int msg_flags) {
    int result;
    struct msghdr msg;
    struct kvec iov;
    sigset_t blocked, oldset;
    //unsigned long pflags = current->flags;
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
            result = kernel_sendmsg(sock, &msg, &iov, 1, size);
        } else
            result = kernel_recvmsg(sock, &msg, &iov, 1, size,
                msg.msg_flags);

        if (signal_pending(current)) {
            siginfo_t info;
            printk(KERN_WARNING "nbd (pid %d: %s) got signal %d\n",
                    task_pid_nr(current), current->comm,
                    dequeue_signal_lock(current, &current->blocked, &info));
            result = -EINTR;
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

static inline int sock_send_bvec(struct socket *sock, struct bio_vec *bvec,
        int flags) {
    int result;
    void *kaddr = kmap(bvec->bv_page);
    result = sock_xmit(sock, 1, kaddr + bvec->bv_offset,
            bvec->bv_len, flags);
    kunmap(bvec->bv_page);
    return result;
}

static inline int sock_recv_bvec(struct socket *sock, struct bio_vec *bvec, char *buf) {
    int result = 0;
    void *kaddr = kmap(bvec->bv_page);
    memcpy(kaddr + bvec->bv_offset, buf, bvec->bv_len);
    result = sock_xmit(sock, 0, kaddr + bvec->bv_offset, bvec->bv_len,
            MSG_WAITALL);
    kunmap(bvec->bv_page);
    return result;
}

static struct request *find_request(struct server *serv, struct request *xreq) {
    struct request *req, *tmp;
    int err;

    list_for_each_entry_safe(req, tmp, &serv->waiting_list, queuelist) {
        if (req != xreq)
            continue;
        list_del_init(&req->queuelist);
        return req;
    }

    err = -ENOENT;
    return ERR_PTR(err);
}

static int dbd_send_thread(void *data) {
    struct server *serv = data;
    struct request *req;
    struct dbd_request dbd_rqst;
    int flags = 0;

    while (!kthread_should_stop()) {
        memset(&dbd_rqst, '\0', sizeof(dbd_rqst));
        wait_event_interruptible(serv->send_wq, kthread_should_stop() || !list_empty(&serv->sending_list));
        if(exit) break;
        req = list_entry(serv->sending_list.next, struct request, queuelist);
        list_del_init(&req->queuelist);
        dbd_rqst.cmd = (rq_data_dir(req) == READ) ? DBD_CMD_IO_READ : DBD_CMD_IO_WRITE;
        dbd_rqst.domain = 1;
        dbd_rqst.addr = /*blk_rq_pos(req)*512;*/((blk_rq_pos(req)*512/UNIT_SIZE)>>serv->mask)*UNIT_SIZE*3+(blk_rq_pos(req)*512)%UNIT_SIZE;
        //dbd_rqst.addr = dbd_rqst.addr * 3;
        dbd_rqst.size = blk_rq_bytes(req);
        memcpy(dbd_rqst.handle, &req, sizeof (req));
        printk("request %p: sending control (%d@%llu,%uB)\n",
                req,
                rq_data_dir(req),
                (unsigned long long) blk_rq_pos(req) << 9,
                blk_rq_bytes(req));
        sock_xmit(serv->sock, 1, &dbd_rqst, sizeof (dbd_rqst), (dbd_rqst.cmd == DBD_CMD_IO_WRITE) ? MSG_MORE : 0);

        if (dbd_rqst.cmd == DBD_CMD_IO_WRITE) {
            struct req_iterator iter;
            struct bio_vec *bvec;

            rq_for_each_segment(bvec, req, iter) {
                flags = 0;
                if (!rq_iter_last(req, iter))
                    flags = MSG_MORE;
                printk("request %p: sending %d bytes data\n", req, bvec->bv_len);
                sock_send_bvec(serv->sock, bvec, flags);
            }
        }
        list_add_tail(&req->queuelist, &serv->waiting_list);
        wake_up(&serv->recv_wq);
    }
    return 0;
}

static int dbd_recv_thread(void *data) {
    struct server *serv = data;
    struct dbd_response dbd_rsps;
    struct request *req;
    int offset;

    while (!kthread_should_stop()) {
        wait_event_interruptible(serv->recv_wq, kthread_should_stop() || !list_empty(&serv->waiting_list));
        if(exit) break;
        sock_xmit(serv->sock, 0, &dbd_rsps, sizeof (dbd_rsps), MSG_WAITALL);
        req = find_request(serv, *(struct request **) dbd_rsps.handle);
        if (rq_data_dir(req) == READ) {
            struct req_iterator iter;
            struct bio_vec *bvec;
            char *buf, *ptr;
            offset = (blk_rq_pos(req)*512) % TUPLE_SIZE;
            buf = (char*)vmalloc(TUPLE_SIZE);
            //sock_xmit(serv->sock, 0, buf, TUPLE_SIZE, MSG_WAITALL);
            ptr = buf + offset;

            rq_for_each_segment(bvec, req, iter) {
                sock_recv_bvec(serv->sock, bvec, ptr);
                printk("request %p: got %d bytes data\n", req, bvec->bv_len);
                ptr+=bvec->bv_len;
            }
            vfree(buf);
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

struct server *find_server(unsigned long addr){
    struct server *serv, *tmp;
    int unit_id = addr/UNIT_SIZE;
    list_for_each_entry_safe(serv, tmp, &dbd_farm->server_list, list_node) {
        if ((unit_id & serv->mask) != serv->id)
            continue;
        return serv;
    }
    return ERR_PTR(-ENOENT);
}

struct dbd_request_wrapper *make_request_wrapper(struct request *req){
    
}

void dbd_req_func(struct request_queue *q) {
    struct request *req;
    struct server *serv;
    while ((req = blk_fetch_request(q)) != NULL) {
        serv = find_server((blk_rq_pos(req) << 9));
        printk("server_id:%d\n", serv->id);
        list_add_tail(&req->queuelist, &serv->sending_list);
        wake_up(&serv->send_wq);
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
    set_capacity(dbd->disk, 10240/5*16);
    add_disk(dbd->disk);
    return 0;
}

void dbd_remove(char *name) {
    blk_cleanup_queue(dbd->disk->queue);
    del_gendisk(dbd->disk);
    put_disk(dbd->disk);
    unregister_blkdev(major, name);
}

void add_server(int id, int mask, char *ip, int port)
{
    struct server *serv = vmalloc(sizeof(struct server));
    serv->id = id;
    serv->mask = mask;
    serv->ip = in_aton(ip);
    serv->port = port;
    INIT_LIST_HEAD(&serv->list_node);
    init_waitqueue_head(&serv->send_wq);
    init_waitqueue_head(&serv->recv_wq);
    INIT_LIST_HEAD(&serv->sending_list);
    INIT_LIST_HEAD(&serv->waiting_list);
    serv->sock = sock_conn(serv->ip, serv->port);
    serv->send_thread = kthread_create(dbd_send_thread, serv, "dbd_send");
    wake_up_process(serv->send_thread);
    serv->recv_thread = kthread_create(dbd_recv_thread, serv, "dbd_recv");
    wake_up_process(serv->recv_thread);
    list_add(&serv->list_node, &dbd_farm->server_list);
}

void remove_servers(void)
{
    struct server *serv, *tmp;
    list_for_each_entry_safe(serv, tmp, &dbd_farm->server_list, list_node) {
        kthread_stop(serv->send_thread);    
        kthread_stop(serv->recv_thread);
        wake_up(&serv->send_wq);
        wake_up(&serv->recv_wq);
        sock_release(serv->sock);
        list_del_init(&serv->list_node);
        vfree(serv);
    }
}
struct socket *sk;
static int __init dbd_init(void) {
    dbd_farm = vmalloc(sizeof(struct farm));
    INIT_LIST_HEAD(&dbd_farm->server_list);
    add_server(0, 1, "127.0.0.1", 8888);
    add_server(1, 1, "127.0.0.1", 9999);
    
    dbd = kcalloc(1, sizeof (*dbd), GFP_KERNEL);
    
    dbd_create();
    return 0;
}

static void __exit dbd_exit(void) {
    exit = 1;
    dbd_remove("dbd");    
    kfree(dbd);
    
    remove_servers();
    vfree(dbd_farm);
}

module_init(dbd_init);
module_exit(dbd_exit);
MODULE_LICENSE("GPL");

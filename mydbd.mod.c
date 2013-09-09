#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x4f1939c7, "per_cpu__current_task" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x573939cb, "alloc_disk" },
	{ 0xe5a6404e, "blk_cleanup_queue" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x1b6314fd, "in_aton" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xaed2f3f9, "sock_release" },
	{ 0xf69f552f, "sock_recvmsg" },
	{ 0x6a9f26c9, "init_timer_key" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x7d11c268, "jiffies" },
	{ 0x343a1a8, "__list_add" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xffc7c184, "__init_waitqueue_head" },
	{ 0xe83fea1, "del_timer_sync" },
	{ 0xde0bdcff, "memset" },
	{ 0x3b700c52, "blk_alloc_queue" },
	{ 0xea147363, "printk" },
	{ 0xecde1418, "_spin_lock_irq" },
	{ 0xce4db10e, "del_gendisk" },
	{ 0xf6d94413, "sock_sendmsg" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6dcaeb88, "per_cpu__kernel_stack" },
	{ 0x71a50dbc, "register_blkdev" },
	{ 0x27418d14, "netlink_unicast" },
	{ 0x46085e4f, "add_timer" },
	{ 0x4c75ad64, "bio_endio" },
	{ 0xb5a459dc, "unregister_blkdev" },
	{ 0x78764f4e, "pv_irq_ops" },
	{ 0x25421969, "__alloc_skb" },
	{ 0x41210112, "blk_queue_make_request" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x1000e51, "schedule" },
	{ 0x8aa14eee, "put_disk" },
	{ 0x266c7c38, "wake_up_process" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0x642e54ac, "__wake_up" },
	{ 0xd2965f6f, "kthread_should_stop" },
	{ 0x37a0cba, "kfree" },
	{ 0xc185e3ce, "kthread_create" },
	{ 0x236c8c64, "memcpy" },
	{ 0x33d92f9a, "prepare_to_wait" },
	{ 0xd7936fb1, "add_disk" },
	{ 0x17084894, "sock_create" },
	{ 0x9ccb2622, "finish_wait" },
	{ 0x207b7e2c, "skb_put" },
	{ 0xe40b105c, "blk_queue_logical_block_size" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A0239C26DD14F638A1F62C5");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 4,
};

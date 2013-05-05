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
	{ 0x3e14d8d6, "blk_init_queue" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x573939cb, "alloc_disk" },
	{ 0xe5a6404e, "blk_cleanup_queue" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x999e8297, "vfree" },
	{ 0x343a1a8, "__list_add" },
	{ 0x8ce3169d, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0xea147363, "printk" },
	{ 0xce4db10e, "del_gendisk" },
	{ 0xd4defbf4, "netlink_kernel_release" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x85f8a266, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6dcaeb88, "per_cpu__kernel_stack" },
	{ 0x71a50dbc, "register_blkdev" },
	{ 0x27418d14, "netlink_unicast" },
	{ 0x1c740bd6, "init_net" },
	{ 0xb5a459dc, "unregister_blkdev" },
	{ 0x25421969, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3d75cbcf, "kfree_skb" },
	{ 0x8aa14eee, "put_disk" },
	{ 0xbc2262ee, "blk_fetch_request" },
	{ 0x12884d17, "__blk_end_request_all" },
	{ 0x37a0cba, "kfree" },
	{ 0x236c8c64, "memcpy" },
	{ 0xd7936fb1, "add_disk" },
	{ 0x207b7e2c, "skb_put" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "AA05AE341BB6C47F09C16BF");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 3,
};

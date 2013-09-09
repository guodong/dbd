#ifdef __KERNEL__

#include <linux/slab.h>
#include <linux/list.h>

#else


#include "include/list.h"

#endif
#include "include/cbt.h"

static int __gfp_kernel = GFP_KERNEL;

#ifdef __KERNEL__
#define ukfree(ptr) kfree(ptr)
#define ukmalloc(size) kmalloc(size, __gfp_kernel)
#else
#define ukfree(ptr) free(ptr)
#define ukmalloc(size) malloc(size)
#endif

cbt_t *cbt_init(void)
{
    cbt_t *cbt = ukmalloc(sizeof(cbt_t));
    cbt->root = NULL;
    INIT_LIST_HEAD(&cbt->nodes);
    return cbt;
}

struct cbt_node *cbt_get_sibling(struct cbt_node *node)
{
    if(node->position == LEFT) {
        return node->parent->right;
    } else {
        return node->parent->left;
    }
}

void cbt_remove_node(struct cbt_node *node)
{
    struct cbt_node *parent = node->parent;
    if(!parent) {
        ukfree(node);
        return;
    }
    if(parent->parent) {
        struct cbt_node *pp = parent->parent;
        if(parent->position == LEFT) {
            ukfree(parent);

            pp->left = cbt_get_sibling(node);
            ukfree(node);

            pp->left->parent = pp;
            pp->left->position = LEFT;
        } else {
            ukfree(parent);
            pp->right = cbt_get_sibling(node);
            ukfree(node);
            pp->right->parent = pp;
            pp->right->position = RIGHT;
        }
    }
}

void cbt_clean(cbt_t *cbt, int clean_data)
{
    struct cbt_node *node, *tmp;

    list_for_each_entry_safe(node, tmp, &cbt->nodes, list_node) {
        if(clean_data) {
            ukfree(node->data);
        }
        list_del_init(&node->list_node);
        cbt_remove_node(node);
    }
    ukfree(cbt);
}

struct cbt_node *cbt_node_init(uint64_t seq, const void *data)
{
    struct cbt_node *node = ukmalloc(sizeof(struct cbt_node));
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->data = (void*)data;
    node->seq = seq;
    return node;
}

int cbt_add_node(cbt_t *cbt, struct cbt_node *node, uint64_t seq)
{
    /*pn is the leaf node*/
    struct cbt_node *pn = cbt->root;
    uint64_t mask = 1;
    struct cbt_node *new_node;

    /*find the leaf pn to split*/
    while(pn->is_leaf == 0) {
        if((node->seq & mask) == LEFT) {
            pn = pn->left;
        } else {
            pn = pn->right;
        }
        mask*=2;
    }
    new_node = cbt_node_init(pn->seq, pn->data);
    new_node->is_leaf = 1;
    new_node->parent = pn;
    pn->is_leaf = 0;
    pn->data = NULL;

    /*if the nodes has the same position bit in the next level, returns error*/
    if((node->seq & mask) == (pn->seq & mask)) {
        cbt_remove_node(new_node);
        return -1;
    }
    pn->right = node;
    pn->left = new_node;

    node->parent = pn;
    list_add_tail(&node->list_node, &cbt->nodes);
    return 0;
}

void cbt_build(struct server_meta *servers, int number)
{

}

struct cbt_node *cbt_search(cbt_t *cbt, uint64_t seq)
{
    struct cbt_node *node = cbt->root;
    uint64_t mask = 1;
    while(node->is_leaf == 1) {
        if((seq & mask) == LEFT) {
            node = node->left;
        } else {
            node = node->right;
        }
    }
    return node;
}

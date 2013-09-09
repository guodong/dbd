#ifndef CBT_H_INCLUDED
#define CBT_H_INCLUDED


struct server_meta {
    char ip[16];
    int port;
    uint64_t seq;
    uint64_t mask;
};

enum cbt_position {
    LEFT = 0,
    RIGHT = 1,
};

struct cbt_node {
    struct cbt_node *left;
    struct cbt_node *right;
    struct cbt_node *parent;
    enum cbt_position position;
    int is_leaf;
    struct list_head list_node; /*used for indexing all nodes*/
    uint64_t seq;
    void *data;
};

typedef struct {
    struct cbt_node *root;
    struct list_head nodes; /*used for indexing all nodes*/
} cbt_t;

cbt_t *cbt_init(void);
void cbt_clean(cbt_t *cbt, int clean_data);
#endif // CBT_H_INCLUDED

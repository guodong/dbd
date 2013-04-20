
#include <linux/types.h>
#include "comm.h"

struct list_head dbd_cache;

struct cache{

};

struct cache_list{
    static struct list_head tuple_list;
};

void encache(struct *tuple)
{

}

int is_cached(int tuple_id)
{
    struct tuple *tp, *tmp;
    list_for_each_entry_safe(tp, tmp, &dbd_cache, tuple){
        if(tp->id == tuple_id){
            return 1;
        }
    }
    return 0;
}

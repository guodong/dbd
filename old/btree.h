/* 
 * File:   btree.h
 * Author: root
 *
 * Created on March 15, 2013, 4:38 PM
 */

#ifndef BTREE_H
#define	BTREE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define NODE_MAX_KEY_NUM 4
    enum node_type{
        INTERNEL,
        LEAF
    };
    struct btnode {
        enum node_type type;
        int num;
        struct {
            unsigned long key;
            int value;          /* index btnode offset or data unit offset in leaf */
        } data[NODE_MAX_KEY_NUM];
        struct btnode *ext_ptr;
    } __attribute__ ((packed));


#ifdef	__cplusplus
}
#endif

#endif	/* BTREE_H */


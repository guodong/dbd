/* 
 * File:   uapi.h
 * Author: root
 *
 * Created on March 25, 2013, 2:33 AM
 */

#ifndef UAPI_H
#define	UAPI_H

#ifdef	__cplusplus
extern "C" {
#endif


#define TUPLE_SIZE (64*1024)
#define UNIT_SIZE (1024*1024*4)

enum dbd_cmd {
    DBD_CMD_IO_READ,
    DBD_CMD_IO_WRITE
};

struct dbd_request {
    int domain;
    enum dbd_cmd cmd;
    char handle[8];
    unsigned long addr;
    unsigned long size;
} __attribute__ ((packed));

struct dbd_response {
    char handle[8];
} __attribute__ ((packed));




#ifdef	__cplusplus
}
#endif

#endif	/* UAPI_H */


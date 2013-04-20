/* 
 * File:   defs.h
 * Author: root
 *
 * Created on April 19, 2013, 9:53 AM
 */

#ifndef DEFS_H
#define	DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

    enum dbd_cmd {
        DBD_CMD_IO_READ,
        DBD_CMD_IO_WRITE,
        DBD_CMD_CTRL_CREATE,
        DBD_CMD_CTRL_REMOVE,
        DBD_CMD_CTRL_UPDATE
    };


#ifdef	__cplusplus
}
#endif

#endif	/* DEFS_H */


#include <linux/types.h>
#define TUPLE_SIZE 4*1024*1024

typedef enum {
    DBD_CMD_READ = 0,
    DBD_CMD_WRITE = 1
} DBD_CMD;

#pragma pack(1)
struct dbd_request {
    DBD_CMD dbd_cmd;
    char handle[8];
    unsigned long addr;
    unsigned long size;
};

struct dbd_response{
    DBD_CMD dbd_cmd;
    char handle[8];
    unsigned long addr;
    unsigned long size;
};
/*enum {
	NBD_CMD_READ = 0,
	NBD_CMD_WRITE = 1,
	NBD_CMD_DISC = 2
};
struct dbd_request {
	__be32 type;	
	char handle[8];
	__be64 from;
	__be32 len;
};
struct dbd_reply {
	__be32 magic;
	__be32 error;		
	char handle[8];		
};*/
#pragma pack(0)

struct tuple {
    int id;
    char data[TUPLE_SIZE];
};

struct request_tuples {
    int first_tuple_id;
    int number;
};

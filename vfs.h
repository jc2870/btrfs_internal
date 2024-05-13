#ifndef _VFS_H
#define _VFS_H
#include "types.h"


struct inode {
	unsigned long		i_ino;
	u64			i_size;
    char *i_name;
    struct hlist_node i_htnode;
};

#endif
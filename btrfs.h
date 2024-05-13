#include "btrfs_tree.h"
#include "rbtree/rbtree.h"

#define BTRFS_SUPER_INFO_OFFSET			0x10000  // from kernel fs/btrfs/fs.h

struct btrfs_fs_info {
    /* logical->physical extent mapping */
	struct rb_root_cached mapping_tree;
};

struct btrfs_chunk_map {
	struct rb_node rb_node;
	
	u64 start;
	u64 chunk_len;
	u64 physical;
};
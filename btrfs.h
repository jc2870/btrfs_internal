#include "btrfs_tree.h"
#include "rbtree/rbtree.h"
#include "types.h"

#define BTRFS_SUPER_INFO_OFFSET			0x10000  // from kernel fs/btrfs/fs.h
#define BTRFS_DEFAULT_NODESIZE 0x4000

/* node is leaf node(struct btrfs_leaf) or internal node(struct btrfs_node) */
struct node {
	char data[BTRFS_DEFAULT_NODESIZE];
	struct list_head list;
};

struct btrfs_root {
	struct list_head leaf_nodes;
};

struct btrfs_fs_info {
    // btrfs image fd
    int fd;

	struct btrfs_super_block *btrfs_sb;

    /* logical->physical extent mapping */
	struct rb_root_cached mapping_tree;

	struct btrfs_root *chunk_root;
	// The root of roots
	struct btrfs_root *roots;
	struct btrfs_root *fs_root;
};

struct btrfs_chunk_map {
	struct rb_node rb_node;

	u64 start;
	u64 chunk_len;
	u64 physical;
};
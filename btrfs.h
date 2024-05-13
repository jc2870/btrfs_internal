#include "btrfs_tree.h"
#include "rbtree/rbtree.h"

#define BTRFS_SUPER_INFO_OFFSET			0x10000  // from kernel fs/btrfs/fs.h
#define BTRFS_DEFAULT_NODESIZE 0x4000

struct btrfs_root {
	char node_buf[BTRFS_DEFAULT_NODESIZE];
	struct btrfs_leaf *leaf;

	struct btrfs_key *key;
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
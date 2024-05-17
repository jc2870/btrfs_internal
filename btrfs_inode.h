/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#ifndef BTRFS_INODE_H
#define BTRFS_INODE_H

#include "btrfs_tree.h"
#include "extent_map.h"
#include "vfs.h"

/*
 * Since we search a directory based on f_pos (struct dir_context::pos) we have
 * to start at 2 since '.' and '..' have f_pos of 0 and 1 respectively, so
 * everybody else has to start at 2 (see btrfs_real_readdir() and dir_emit_dots()).
 */
#define BTRFS_DIR_START_INDEX 2

/*
 * ordered_data_close is set by truncate when a file that used
 * to have good data has been truncated to zero.  When it is set
 * the btrfs file release call will add this inode to the
 * ordered operations list so that we make sure to flush out any
 * new data the application may have written before commit.
 */
enum {
	BTRFS_INODE_FLUSH_ON_CLOSE,
	BTRFS_INODE_DUMMY,
	BTRFS_INODE_IN_DEFRAG,
	BTRFS_INODE_HAS_ASYNC_EXTENT,
	 /*
	  * Always set under the VFS' inode lock, otherwise it can cause races
	  * during fsync (we start as a fast fsync and then end up in a full
	  * fsync racing with ordered extent completion).
	  */
	BTRFS_INODE_NEEDS_FULL_SYNC,
	BTRFS_INODE_COPY_EVERYTHING,
	BTRFS_INODE_IN_DELALLOC_LIST,
	BTRFS_INODE_HAS_PROPS,
	BTRFS_INODE_SNAPSHOT_FLUSH,
	/*
	 * Set and used when logging an inode and it serves to signal that an
	 * inode does not have xattrs, so subsequent fsyncs can avoid searching
	 * for xattrs to log. This bit must be cleared whenever a xattr is added
	 * to an inode.
	 */
	BTRFS_INODE_NO_XATTRS,
	/*
	 * Set when we are in a context where we need to start a transaction and
	 * have dirty pages with the respective file range locked. This is to
	 * ensure that when reserving space for the transaction, if we are low
	 * on available space and need to flush delalloc, we will not flush
	 * delalloc for this inode, because that could result in a deadlock (on
	 * the file range, inode's io_tree).
	 */
	BTRFS_INODE_NO_DELALLOC_FLUSH,
	/*
	 * Set when we are working on enabling verity for a file. Computing and
	 * writing the whole Merkle tree can take a while so we want to prevent
	 * races where two separate tasks attempt to simultaneously start verity
	 * on the same file.
	 */
	BTRFS_INODE_VERITY_IN_PROGRESS,
	/* Set when this inode is a free space inode. */
	BTRFS_INODE_FREE_SPACE_INODE,
	/* Set when there are no capabilities in XATTs for the inode. */
	BTRFS_INODE_NO_CAP_XATTR,
};

/* in memory btrfs inode */
struct btrfs_inode {
	/* which subvolume this inode belongs to */
	struct btrfs_root *root;

	/* key used to find this inode on disk.  This is used by the code
	 * to read in roots of subvolumes
	 */
	struct btrfs_key location;

	/* Cached value of inode property 'compression'. */
	u8 prop_compress;

	/*
	 * Force compression on the file using the defrag ioctl, could be
	 * different from prop_compress and takes precedence if set.
	 */
	u8 defrag_compress;

	/* the extent_tree has caches of all the extent mappings to disk */
	struct extent_map_tree extent_tree;

	/*
	 * Keep track of where the inode has extent items mapped in order to
	 * make sure the i_size adjustments are accurate. Not required when the
	 * filesystem is NO_HOLES, the status can't be set while mounted as
	 * it's a mkfs-time feature.
	 */
	struct extent_io_tree *file_extent_tree;

	/* held while logging the inode in tree-log.c */
	// struct mutex log_mutex;

	/*
	 * Counters to keep track of the number of extent item's we may use due
	 * to delalloc and such.  outstanding_extents is the number of extent
	 * items we think we'll end up using, and reserved_extents is the number
	 * of extent items we've reserved metadata for. Protected by 'lock'.
	 */
	unsigned outstanding_extents;

	/* used to order data wrt metadata */
	struct rb_root ordered_tree;
	struct rb_node *ordered_tree_last;

	/* list of all the delalloc inodes in the FS.  There are times we need
	 * to write all the delalloc pages to disk, and this list is used
	 * to walk them all.
	 */
	struct list_head delalloc_inodes;

	/* node for the red-black tree that links inodes in subvolume root */
	struct rb_node rb_node;

	unsigned long runtime_flags;

	/* full 64 bit generation number, struct vfs_inode doesn't have a big
	 * enough field for this.
	 */
	u64 generation;

	/*
	 * ID of the transaction handle that last modified this inode.
	 * Protected by 'lock'.
	 */
	u64 last_trans;

	/*
	 * ID of the transaction that last logged this inode.
	 * Protected by 'lock'.
	 */
	u64 logged_trans;

	/*
	 * Log transaction ID when this inode was last modified.
	 * Protected by 'lock'.
	 */
	int last_sub_trans;

	/* A local copy of root's last_log_commit. Protected by 'lock'. */
	int last_log_commit;

	union {
		/*
		 * Total number of bytes pending delalloc, used by stat to
		 * calculate the real block usage of the file. This is used
		 * only for files. Protected by 'lock'.
		 */
		u64 delalloc_bytes;
		/*
		 * The lowest possible index of the next dir index key which
		 * points to an inode that needs to be logged.
		 * This is used only for directories.
		 * Use the helpers btrfs_get_first_dir_index_to_log() and
		 * btrfs_set_first_dir_index_to_log() to access this field.
		 */
		u64 first_dir_index_to_log;
	};

	union {
		/*
		 * Total number of bytes pending delalloc that fall within a file
		 * range that is either a hole or beyond EOF (and no prealloc extent
		 * exists in the range). This is always <= delalloc_bytes and this
		 * is used only for files. Protected by 'lock'.
		 */
		u64 new_delalloc_bytes;
		/*
		 * The offset of the last dir index key that was logged.
		 * This is used only for directories.
		 */
		u64 last_dir_index_offset;
	};

	/*
	 * Total number of bytes pending defrag, used by stat to check whether
	 * it needs COW. Protected by 'lock'.
	 */
	u64 defrag_bytes;

	/*
	 * The size of the file stored in the metadata on disk.  data=ordered
	 * means the in-memory i_size might be larger than the size on disk
	 * because not all the blocks are written yet. Protected by 'lock'.
	 */
	u64 disk_i_size;

	/*
	 * If this is a directory then index_cnt is the counter for the index
	 * number for new files that are created. For an empty directory, this
	 * must be initialized to BTRFS_DIR_START_INDEX.
	 */
	u64 index_cnt;

	/* Cache the directory index number to speed the dir/file remove */
	u64 dir_index;

	/* the fsync log has some corner cases that mean we have to check
	 * directories to see if any unlinks have been done before
	 * the directory was logged.  See tree-log.c for all the
	 * details
	 */
	u64 last_unlink_trans;

	/*
	 * The id/generation of the last transaction where this inode was
	 * either the source or the destination of a clone/dedupe operation.
	 * Used when logging an inode to know if there are shared extents that
	 * need special care when logging checksum items, to avoid duplicate
	 * checksum items in a log (which can lead to a corruption where we end
	 * up with missing checksum ranges after log replay).
	 * Protected by the vfs inode lock.
	 */
	u64 last_reflink_trans;

	/*
	 * Number of bytes outstanding that are going to need csums.  This is
	 * used in ENOSPC accounting. Protected by 'lock'.
	 */
	u64 csum_bytes;

	/* Backwards incompatible flags, lower half of inode_item::flags  */
	u32 flags;
	/* Read-only compatibility flags, upper half of inode_item::flags */
	u32 ro_flags;

	struct btrfs_delayed_node *delayed_node;

	/* File creation time. */
	u64 i_otime_sec;
	u32 i_otime_nsec;

	/* Hook into fs_info->delayed_iputs */
	struct list_head delayed_iput;

	struct inode vfs_inode;
};

static inline u64 btrfs_get_first_dir_index_to_log(const struct btrfs_inode *inode)
{
	return inode->first_dir_index_to_log;
}

static inline void btrfs_set_first_dir_index_to_log(struct btrfs_inode *inode,
						    u64 index)
{
	inode->first_dir_index_to_log = index;
}

static inline struct btrfs_inode *BTRFS_I(const struct inode *inode)
{
	return container_of(inode, struct btrfs_inode, vfs_inode);
}


#if BITS_PER_LONG == 32

/*
 * On 32 bit systems the i_ino of struct inode is 32 bits (unsigned long), so
 * we use the inode's location objectid which is a u64 to avoid truncation.
 */
static inline u64 btrfs_ino(const struct btrfs_inode *inode)
{
	u64 ino = inode->location.objectid;

	/* type == BTRFS_ROOT_ITEM_KEY: subvol dir */
	if (inode->location.type == BTRFS_ROOT_ITEM_KEY)
		ino = inode->vfs_inode.i_ino;
	return ino;
}

#else

static inline u64 btrfs_ino(const struct btrfs_inode *inode)
{
	return inode->vfs_inode.i_ino;
}

#endif

#endif

/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_EXTENT_MAP_H
#define BTRFS_EXTENT_MAP_H
#include "rbtree/rbtree.h"
#include "types.h"

#define EXTENT_MAP_LAST_BYTE ((u64)-4)
#define EXTENT_MAP_HOLE ((u64)-3)
#define EXTENT_MAP_INLINE ((u64)-2)

/*
 * Keep this structure as compact as possible, as we can have really large
 * amounts of allocated extent maps at any time.
 */
struct extent_map {
	struct rb_node rb_node;

	/* all of these are in bytes */
	u64 start;
	u64 len;
	u64 mod_start;
	u64 mod_len;
	u64 orig_start;
	u64 orig_block_len;
	u64 ram_bytes;
	u64 block_start;
	u64 block_len;

	/*
	 * Generation of the extent map, for merged em it's the highest
	 * generation of all merged ems.
	 * For non-merged extents, it's from btrfs_file_extent_item::generation.
	 */
	u64 generation;
	u32 flags;
	refcount_t refs;
	struct list_head list;
};

struct extent_map_tree {
	struct rb_root_cached map;
	struct list_head modified_extents;
};

struct btrfs_inode;


static inline int extent_map_in_tree(const struct extent_map *em)
{
	return !RB_EMPTY_NODE(&em->rb_node);
}

static inline u64 extent_map_end(const struct extent_map *em)
{
	if (em->start + em->len < em->start)
		return (u64)-1;
	return em->start + em->len;
}

void extent_map_tree_init(struct extent_map_tree *tree);
struct extent_map *lookup_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len);
void remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em);
int split_extent_map(struct btrfs_inode *inode, u64 start, u64 len, u64 pre,
		     u64 new_logical);

struct extent_map *alloc_extent_map(void);
void free_extent_map(struct extent_map *em);
int unpin_extent_cache(struct btrfs_inode *inode, u64 start, u64 len, u64 gen);
void clear_em_logging(struct extent_map_tree *tree, struct extent_map *em);
struct extent_map *search_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len);
int btrfs_add_extent_mapping(struct btrfs_fs_info *fs_info,
			     struct extent_map_tree *em_tree,
			     struct extent_map **em_in, u64 start, u64 len);
void btrfs_drop_extent_map_range(struct btrfs_inode *inode,
				 u64 start, u64 end,
				 bool skip_pinned);
int btrfs_replace_extent_map_range(struct btrfs_inode *inode,
				   struct extent_map *new_em,
				   bool modified);

#endif

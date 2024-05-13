#include <asm-generic/errno-base.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "btrfs_tree.h"
#include "btrfs.h"

#define check_error(cond, error) \
do {    \
    if (cond) { \
        error;  \
        exit(EXIT_FAILURE); \
    }\
} while(0)

#define btrfs_err(fmt, args...) \
do {    \
    fprintf(stderr, "func: %s line: %u\t\tMSG: " fmt, __func__, __LINE__, ##args);   \
} while(0)

#define BTRFS_DEFAULT_NODESIZE 0x4000

int btrfs_read_sb(struct btrfs_super_block *btrfs_sb, const char *img_name)
{
    int fd;
    int ret;

    fd = open(img_name, O_RDONLY);
    check_error(fd == -1, perror("open"));
    ret = pread(fd, btrfs_sb, sizeof(struct btrfs_super_block), BTRFS_SUPER_INFO_OFFSET);
    check_error(ret != sizeof(struct btrfs_super_block), perror("read"));
    check_error(btrfs_sb->magic != BTRFS_MAGIC, btrfs_err("bad magic number\n"));

    return fd;
}

static inline unsigned long btrfs_chunk_item_size(int num_stripes)
{
	check_error(!num_stripes, btrfs_err("bad stripes\n"));
	return sizeof(struct btrfs_chunk) +
		sizeof(struct btrfs_stripe) * (num_stripes - 1);
}

struct btrfs_chunk_map *btrfs_find_chunk_map_nolock(struct btrfs_fs_info *fs_info,
						    u64 logical, u64 length)
{
	struct rb_node *node = fs_info->mapping_tree.rb_root.rb_node;
	struct rb_node *prev = NULL;
	struct rb_node *orig_prev;
	struct btrfs_chunk_map *map;
	struct btrfs_chunk_map *prev_map = NULL;

	while (node) {
		map = rb_entry(node, struct btrfs_chunk_map, rb_node);
		prev = node;
		prev_map = map;

		if (logical < map->start) {
			node = node->rb_left;
		} else if (logical >= map->start + map->chunk_len) {
			node = node->rb_right;
		} else {
			return map;
		}
	}

	if (!prev)
		return NULL;

	orig_prev = prev;
	while (prev && logical >= prev_map->start + prev_map->chunk_len) {
		prev = rb_next(prev);
		prev_map = rb_entry(prev, struct btrfs_chunk_map, rb_node);
	}

	if (!prev) {
		prev = orig_prev;
		prev_map = rb_entry(prev, struct btrfs_chunk_map, rb_node);
		while (prev && logical < prev_map->start) {
			prev = rb_prev(prev);
			prev_map = rb_entry(prev, struct btrfs_chunk_map, rb_node);
		}
	}

	if (prev) {
		u64 end = logical + length;

		/*
		 * Caller can pass a U64_MAX length when it wants to get any
		 * chunk starting at an offset of 'logical' or higher, so deal
		 * with underflow by resetting the end offset to U64_MAX.
		 */
		if (end < logical)
			end = ULLONG_MAX;

		if (end > prev_map->start &&
		    logical < prev_map->start + prev_map->chunk_len) {
			return prev_map;
		}
	}

	return NULL;
}

int btrfs_insert_map_node(struct btrfs_fs_info *fs_info, struct btrfs_chunk_map *map)
{
    struct rb_node **p;
	struct rb_node *parent = NULL;
	bool leftmost = true;

	p = &fs_info->mapping_tree.rb_root.rb_node;
	while (*p) {
		struct btrfs_chunk_map *entry;

		parent = *p;
		entry = rb_entry(parent, struct btrfs_chunk_map, rb_node);

		if (map->start < entry->start) {
			p = &(*p)->rb_left;
		} else if (map->start > entry->start) {
			p = &(*p)->rb_right;
			leftmost = false;
		} else {
			return -EEXIST;
		}
	}
	rb_link_node(&map->rb_node, parent, p);
	rb_insert_color_cached(&map->rb_node, &fs_info->mapping_tree, leftmost);

	return 0;
}

// @TODO: support multi stripe
void btrfs_add_chunk_map(struct btrfs_fs_info *fs_info, struct btrfs_key *key, struct btrfs_chunk *chunk)
{
    u64 logical = key->offset;
    struct btrfs_chunk_map *map = NULL;

    map = btrfs_find_chunk_map_nolock(fs_info,  logical, 1);
    if (map) {
        // already exist
        return;
    }

    map = malloc(sizeof(*map));
    check_error(!map, btrfs_err("oom\n"));

    RB_CLEAR_NODE(&map->rb_node);
    map->chunk_len = chunk->length;
    map->start = logical;
    // @NOTE: only support single stripe until yet
    map->physical = chunk->stripe.offset;
    btrfs_insert_map_node(fs_info, map);
}

void btrfs_read_sys_chunk(struct btrfs_super_block *btrfs_sb, struct btrfs_fs_info *fs_info)
{
    u32 array_size = btrfs_sb->sys_chunk_array_size;
    u8 *array_ptr = btrfs_sb->sys_chunk_array;
    struct btrfs_chunk *chunk;
    struct btrfs_key *key;
    u32 offset = 0;
    u32 len = 0;

    while (offset < array_size) {
        key = (struct btrfs_key *)array_ptr;
        len = sizeof(*key);
        check_error(offset > array_size, btrfs_err("short read\n"));
        check_error(key->type != BTRFS_CHUNK_ITEM_KEY, btrfs_err("unexpected item type %u in sys_array at offset %u\n", key->type, offset));

        array_ptr += len;
        offset += len;

        chunk = (struct btrfs_chunk*)array_ptr;
        len = btrfs_chunk_item_size(1);
        check_error(len + offset > array_size, btrfs_err("short read\n"));
        check_error(!chunk->num_stripes, btrfs_err("invalid number of stripes %u in sys_array at offset %u\n", chunk->num_stripes, offset));
        check_error(!(chunk->type & BTRFS_BLOCK_GROUP_SYSTEM), btrfs_err("invalid chunk type %llu in sys_array at offset %u\n", chunk->type, offset));

        len = btrfs_chunk_item_size(chunk->num_stripes);
        check_error(offset + len > array_size, btrfs_err("short read\n"));

        btrfs_add_chunk_map(fs_info, key, chunk);

        offset += len;
        array_ptr += len;
    }
}

// @return: the physical offset corresponding to logical
u64 btrfs_map_block(struct btrfs_fs_info *fs_info, u64 logical, __le32 length)
{
    struct btrfs_chunk_map *map;

    map = btrfs_find_chunk_map_nolock(fs_info, logical, length);
    check_error(!map, btrfs_err("no mapping from %llu len %u exists\n", logical, length));

    return logical - map->start + map->physical;
}

void btrfs_read_leaf(struct btrfs_fs_info *fs_info, const char* node_buf, struct btrfs_leaf *leaf)
{
    int i = 0;
    int ret;
    u32 offset = sizeof(struct btrfs_header);

    while (i < leaf->header.nritems) {
        leaf->items[i] = *(struct btrfs_item*)(node_buf + offset);

        // only support chunk item
        if (leaf->items[i].key.type == BTRFS_CHUNK_ITEM_KEY) {
            struct btrfs_chunk *chunk = (struct btrfs_chunk *)(leaf->items[i].offset + (node_buf + sizeof(struct btrfs_header)));

            btrfs_add_chunk_map(fs_info, (struct btrfs_key*)&leaf->items[i].key, chunk);
        }

        i++;
        offset += sizeof(struct btrfs_item);
    }
}

// don't support yet
void btrfs_read_internal_node()
{

}

void btrfs_read_chunk_tree(struct btrfs_super_block *btrfs_sb, struct btrfs_fs_info *fs_info)
{
    const u8 default_chunk_uuid[] = {0x5, 0xf5, 0xe9, 0x21, 0x7, 0x4a, 0x42, 0xe1,
                                     0xa9, 0x2e, 0x3d, 0x81, 0x76, 0xa8, 0x2c, 0x6c};
    struct btrfs_header header;
    char node_buf[BTRFS_DEFAULT_NODESIZE] = {0};
    struct btrfs_leaf *leaf = NULL;
    u64 logical = btrfs_sb->chunk_root;
    u32 length = btrfs_sb->nodesize;
    int ret;
    int i;

    ret = pread(fs_info->fd, &node_buf, sizeof(node_buf), btrfs_map_block(fs_info, logical, BTRFS_DEFAULT_NODESIZE));
    check_error(ret != sizeof(node_buf), btrfs_err("bad read\n"));
    memcpy(&header, node_buf, sizeof(struct btrfs_header));
    // Selftest: The data here is the same as the data read from kernel, but uuid check failed... Why?
    // check_error(memcmp(default_chunk_uuid, header.chunk_tree_uuid, sizeof(default_chunk_uuid)), btrfs_err("bad uuid\n"));

    if (header.level == 0) {
        leaf = malloc(sizeof(struct btrfs_item) * header.nritems + sizeof(struct btrfs_header));
        leaf->header = header;
        btrfs_read_leaf(fs_info, node_buf, leaf);
    } else {
        btrfs_read_internal_node();
    }
}

int main (int argc, char **argv)
{
    struct btrfs_super_block btrfs_sb;
    struct btrfs_fs_info fs_info = {0};

    check_error(argc != 2, printf("USAGE: %s $btrfs_img\n", argv[0]));
    fs_info.fd = btrfs_read_sb(&btrfs_sb, argv[1]);
    btrfs_read_sys_chunk(&btrfs_sb, &fs_info);
    btrfs_read_chunk_tree(&btrfs_sb, &fs_info);
    return 0;
}
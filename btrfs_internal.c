#include <asm-generic/errno-base.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#include "btrfs_tree.h"
#include "btrfs.h"
#include "lib.h"
#include "types.h"
#include "vfs.h"

DECLARE_HASHTABLE(inodes_hlist, 10);

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

#define BTRFS_FILE_EXTENT_INLINE_DATA_START		\
		(offsetof(struct btrfs_file_extent_item, disk_bytenr))

static struct btrfs_root_item *fs_root_item = NULL;
static char file_names[20][20];
static u32 file_inodes[20];
static u32 file_num = 0;

typedef void(*btrfs_item_handler)(struct btrfs_fs_info*, struct btrfs_item*, void*);

static inline u64 inode_hash(u64 ino)
{
    return crc64(&ino, sizeof(ino));
}

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

void btrfs_read_sys_chunk(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;
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

void btrfs_read_leaf(struct btrfs_fs_info *fs_info, struct btrfs_root *root, struct btrfs_leaf *leaf, btrfs_item_handler item_handler)
{
    int i = 0;
    int ret;
    u32 offset = sizeof(struct btrfs_header);
    struct btrfs_item *item = NULL;
    const char* node_buf = root->node_buf;

    while (i < leaf->header.nritems) {
        item = (struct btrfs_item*)(node_buf + offset);
        leaf->items[i] = *item;
        u32 type = leaf->items[i].key.type;
        void* data_ptr = (void*)(leaf->items[i].offset + (node_buf + sizeof(struct btrfs_header)));

        item_handler(fs_info, item, data_ptr);

        i++;
        offset += sizeof(struct btrfs_item);
    }
}

// don't support yet
void btrfs_read_internal_node()
{
    check_error(1, btrfs_err("don't support yet\n"));
}

void btrfs_read_tree(struct btrfs_root *root, struct btrfs_fs_info *fs_info, u64 logical, btrfs_item_handler item_handler)
{
    struct btrfs_header header;
    char *node_buf = root->node_buf;
    struct btrfs_leaf *leaf = NULL;
    int ret;

    ret = pread(fs_info->fd, node_buf, BTRFS_DEFAULT_NODESIZE, btrfs_map_block(fs_info, logical, BTRFS_DEFAULT_NODESIZE));
    check_error(ret != BTRFS_DEFAULT_NODESIZE, btrfs_err("bad read\n"));
    memcpy(&header, node_buf, sizeof(struct btrfs_header));

    if (header.level == 0) {
        leaf = malloc(sizeof(struct btrfs_item) * header.nritems + sizeof(struct btrfs_header));
        check_error(!leaf, btrfs_err("oom\n"));

        leaf->header = header;
        btrfs_read_leaf(fs_info, root, leaf, item_handler);
        root->leaf = leaf;
    } else {
        btrfs_read_internal_node();
    }
}

void* btrfs_alloc_root()
{
    struct btrfs_root *root= malloc(sizeof(*root));
    check_error(!root, btrfs_err("oom\n"));

    root->key = malloc(sizeof(struct btrfs_key));
    check_error(!root->key, btrfs_err("oom\n"));

    return root;
}

void btrfs_chunk_item_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;
    struct btrfs_chunk* chunk = (struct btrfs_chunk*)data_ptr;

    if (type == BTRFS_CHUNK_ITEM_KEY) {
        // type BTRFS_CHUNK_ITEM_KEY corresponding to struct btrfs_chunk
        struct btrfs_chunk *chunk = (struct btrfs_chunk *)data_ptr;

        btrfs_add_chunk_map(fs_info, (struct btrfs_key*)&item->key, chunk);
        memcpy(fs_info->chunk_root->key, &item->key, sizeof(struct btrfs_key));
    }
}

void btrfs_root_item_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_ROOT_ITEM_KEY && item->key.objectid == BTRFS_FS_TREE_OBJECTID) {
        // type BTRFS_ROOT_ITEM_KEY corresponding to struct btrfs_root_item
        struct btrfs_root_item *root = (struct btrfs_root_item*)data_ptr;

        fs_root_item = root;
    }
}

static inline char* btrfs_file_extent_inline_start(
				const struct btrfs_file_extent_item *e)
{
	return (char*)e + BTRFS_FILE_EXTENT_INLINE_DATA_START;
}

void btrfs_dir_index_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_DIR_INDEX_KEY) {
        // type BTRFS_DIR_INDEX_KEY corresponding to struct btrfs_dir_item
        struct btrfs_dir_item* dir_item = (struct btrfs_dir_item*)data_ptr;

        memcpy(file_names[file_num], (char*)(dir_item+1), dir_item->name_len);
        file_inodes[file_num] = dir_item->location.objectid;
        file_num++;
    } else if (type == BTRFS_INODE_ITEM_KEY) {
        /* See btrfs_read_locked_inode() */
        struct btrfs_inode_item *inode_item = (struct btrfs_inode_item*)data_ptr;
        // printf("inode: %lld size: %lld mode:0x%x\n", item->key.objectid, inode_item->size, inode_item->mode);
    }else if (type == BTRFS_EXTENT_DATA_KEY) {
        struct btrfs_file_extent_item *e_item = (struct btrfs_file_extent_item*)data_ptr;
        if (e_item->type == BTRFS_FILE_EXTENT_REG || e_item-> type == BTRFS_FILE_EXTENT_PREALLOC) {
            if (e_item->compression != BTRFS_COMPRESS_NONE) {
                fprintf(stderr, "don't support compression yet\n");
                exit(EXIT_FAILURE);
            }
            int block_start = e_item->disk_bytenr + e_item->offset;
            int len = e_item->num_bytes;
            assert(len == 8192);
            printf("found file\n");
            char *data = malloc(8192);
            pread(fs_info->fd, data, len, btrfs_map_block(fs_info, block_start, len));

            int fd = open("ret", O_CREAT|O_RDWR | O_TRUNC, 0644);
            check_error(fd < 0, printf("open ret file failed\n"));
            write(fd, data, len);
            close(fd);

            free(data);
        } else if (e_item->type == BTRFS_FILE_EXTENT_INLINE) {
            int size = e_item->ram_bytes;
            char *data = malloc(size + 1);
            memcpy(data,  btrfs_file_extent_inline_start(e_item), size);
            // printf("data: %s", data);
            free(data);
        }
    }
}

void btrfs_read_chunk_tree(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;
    struct btrfs_header *header;

    btrfs_read_tree(fs_info->chunk_root, fs_info, btrfs_sb->chunk_root, btrfs_chunk_item_handler);
}

static void btrfs_read_root_tree(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;

    btrfs_read_tree(fs_info->roots, fs_info, btrfs_sb->root, btrfs_root_item_handler);
}

static void btrfs_read_fs_tree(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;

    btrfs_read_tree(fs_info->fs_root, fs_info, fs_root_item->bytenr, btrfs_dir_index_handler);
}

static void show_result()
{
    int i = 0;
    struct inode *inode;

    hash_for_each(inodes_hlist, i, inode, i_htnode) {
        printf("inode: %lu, name %s\n", inode->i_ino, inode->i_name);
    }
}

static void init()
{
    crc_init();
    hash_init(inodes_hlist);
}

static void alloc_and_init_inode(struct btrfs_dir_item *dir_item)
{
    struct inode *inode = malloc(sizeof(*inode));
    memset(inode, 0, sizeof(*inode));
    inode->i_ino = dir_item->location.objectid;
    hash_add(inodes_hlist, &inode->i_htnode, inode_hash(inode->i_ino));
    inode->i_name = malloc(dir_item->name_len + 1);
    inode->i_name[dir_item->name_len] = '\0';
    memcpy(inode->i_name, (char*)(dir_item+1), dir_item->name_len);
}

void get_all_inodes_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_DIR_INDEX_KEY) {
        // type BTRFS_DIR_INDEX_KEY corresponding to struct btrfs_dir_item
        struct btrfs_dir_item* dir_item = (struct btrfs_dir_item*)data_ptr;

        alloc_and_init_inode(dir_item);
    }
}

static void get_all_inodes(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;

    btrfs_read_tree(fs_info->fs_root, fs_info, fs_root_item->bytenr, get_all_inodes_handler);
}

int main (int argc, char **argv)
{
    struct btrfs_super_block btrfs_sb;
    struct btrfs_fs_info *fs_info;

    check_error(argc != 2, printf("USAGE: %s $btrfs_img\n", argv[0]));
    init();

    fs_info = malloc(sizeof(*fs_info));
    check_error(!fs_info, btrfs_err("oom\n"));

    fs_info->fd = btrfs_read_sb(&btrfs_sb, argv[1]);
    fs_info->btrfs_sb = &btrfs_sb;

    fs_info->chunk_root = btrfs_alloc_root();
    fs_info->fs_root = btrfs_alloc_root();
    fs_info->roots = btrfs_alloc_root();

    btrfs_read_sys_chunk(fs_info);
    btrfs_read_chunk_tree(fs_info);
    // The root tree
    btrfs_read_root_tree(fs_info);
    btrfs_read_fs_tree(fs_info);
    get_all_inodes(fs_info);

    show_result();
    return 0;
}
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/xattr.h>

#include "btrfs_tree.h"
#include "btrfs.h"
#include "lib.h"
#include "types.h"
#include "vfs.h"
#include "btrfs_inode.h"

#define BTRFS_HASH_BITS 10
#define BTRFS_ROOT_INO 256
#define MAX_PATH_LEN 256

DECLARE_HASHTABLE(inodes_hlist, BTRFS_HASH_BITS);
DEFINE_FREE(free, char*, if (_T) free(_T))

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
static u32 inodes_num = 0;
static volatile bool all_same = true;
static const char *restore_path = NULL;
static struct node *alloc_node();
static struct btrfs_fs_info *fs_info = NULL;
static void get_all_inodes_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr);
static struct inode *get_inode_by_ino(u64 ino);

typedef void(*btrfs_item_handler)(struct btrfs_fs_info*, struct btrfs_item*, void*);

static inline u64 inode_hash(u64 ino)
{
    return crc64(&ino, sizeof(ino));
}

int btrfs_read_sb(struct btrfs_super_block *btrfs_sb, const char *img_name)
{
    int fd;
    ssize_t ret;

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
    struct rb_node *node = NULL;

    for (node = rb_first_cached(&fs_info->mapping_tree); node; node = rb_next(node)) {
        struct btrfs_chunk_map *map;

        map = rb_entry(node, struct btrfs_chunk_map, rb_node);
        if (map->start <= logical && map->start + map->chunk_len > logical + length) {
            return map;
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
    if (map->physical != map->start) {
        all_same = false;
    }
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
    u64 len = 0;

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
u64 btrfs_map_block(struct btrfs_fs_info *fs_info, u64 logical, u64 length)
{
    struct btrfs_chunk_map *map;

    if (all_same) {
        return logical;
    }

    map = btrfs_find_chunk_map_nolock(fs_info, logical, length);
    check_error(!map, btrfs_err("no mapping from %lu len %lu exists\n", logical, length));

    return logical - map->start + map->physical;
}

void btrfs_read_leaf(struct btrfs_fs_info *fs_info, struct btrfs_root *root, struct btrfs_leaf *leaf, btrfs_item_handler item_handler)
{
    u32 i = 0;
    u32 offset = sizeof(struct btrfs_header);
    struct btrfs_item *item = NULL;
    const char* node_buf = (const char*)leaf;

    while (i < leaf->header.nritems) {
        item = (struct btrfs_item*)(node_buf + offset);
        leaf->items[i] = *item;
        void* data_ptr = (void*)(leaf->items[i].offset + (node_buf + sizeof(struct btrfs_header)));

        item_handler(fs_info, item, data_ptr);

        i++;
        offset += sizeof(struct btrfs_item);
    }
}

static __always_inline struct btrfs_key_ptr *
nr_key_ptr(struct btrfs_node* node, int n)
{
    size_t s_header = sizeof(struct btrfs_header);
    size_t s_key = sizeof(struct btrfs_key_ptr);
    return (struct btrfs_key_ptr*)(((char*)node) + s_header + s_key*n);
}

static inline void btrfs_read_node(char *dst, u64 bytenr)
{
    u64 offset = btrfs_map_block(fs_info, bytenr, BTRFS_DEFAULT_NODESIZE);
    ssize_t ret = pread(fs_info->fd, dst, BTRFS_DEFAULT_NODESIZE, offset);

    check_error(ret != BTRFS_DEFAULT_NODESIZE, btrfs_err("short read\n"));
}

void btrfs_read_internal_node(struct btrfs_root *root, struct btrfs_node *internal_node)
{
    u32 i = 0;

    for (i = 0; i < internal_node->header.nritems; ++i) {
        struct btrfs_key_ptr *key_ptr = nr_key_ptr(internal_node, i);
        struct node *node = alloc_node();
        check_error(!node, btrfs_err("oom\n"));
        btrfs_read_node(node->data, key_ptr->blockptr);
        if (((struct btrfs_header*)node->data)->level == 0) {
            list_add_tail(&node->list, &root->leaf_nodes);
        } else {
            btrfs_read_internal_node(root, (void*)node);
            free(node);
        }
    }
}

static struct node *alloc_node()
{
    struct node *node = malloc(sizeof(*node));

    check_error(!node, printf("oom\n"));
    memset(node, 0, sizeof(*node));
    INIT_LIST_HEAD(&node->list);

    return node;
}

void btrfs_read_tree(struct btrfs_root *root, struct btrfs_fs_info *fs_info, u64 logical)
{
    struct btrfs_header *header;
    struct node *node = alloc_node();

    btrfs_read_node(node->data, logical);
    header = (struct btrfs_header*)node->data;

    if (header->level == 0) {
        list_add_tail(&node->list, &root->leaf_nodes);
    } else {
        btrfs_read_internal_node(root, (void*)node->data);
        free(node);
    }
}

void* btrfs_alloc_root()
{
    struct btrfs_root *root= malloc(sizeof(*root));

    check_error(!root, btrfs_err("oom\n"));
    INIT_LIST_HEAD(&root->leaf_nodes);

    return root;
}

void btrfs_chunk_item_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_CHUNK_ITEM_KEY) {
        // type BTRFS_CHUNK_ITEM_KEY corresponding to struct btrfs_chunk
        struct btrfs_chunk *chunk = (struct btrfs_chunk *)data_ptr;

        btrfs_add_chunk_map(fs_info, (struct btrfs_key*)&item->key, chunk);
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

void btrfs_read_chunk_tree(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;
    struct node *node;

    btrfs_read_tree(fs_info->chunk_root, fs_info, btrfs_sb->chunk_root);
    list_for_each_entry(node, &fs_info->chunk_root->leaf_nodes, list) {
        struct btrfs_leaf *leaf = (struct btrfs_leaf*)node->data;
        btrfs_read_leaf(fs_info, fs_info->chunk_root, leaf, btrfs_chunk_item_handler);
    }
}

static void btrfs_read_root_tree(struct btrfs_fs_info *fs_info)
{
    struct btrfs_super_block *btrfs_sb = fs_info->btrfs_sb;
    struct node *node;

    btrfs_read_tree(fs_info->roots, fs_info, btrfs_sb->root);
    list_for_each_entry(node, &fs_info->roots->leaf_nodes, list) {
        struct btrfs_leaf *leaf = (struct btrfs_leaf*)node->data;
        btrfs_read_leaf(fs_info, fs_info->roots, leaf, btrfs_root_item_handler);
    }
    check_error(fs_root_item == NULL, btrfs_err("cannot find fs root\n"));
}

static void btrfs_read_fs_tree(struct btrfs_fs_info *fs_info)
{
    struct node *node;
    u32 i = 0;

    btrfs_read_tree(fs_info->fs_root, fs_info, fs_root_item->bytenr);
    list_for_each_entry(node, &fs_info->fs_root->leaf_nodes, list) {
        i++;
    }
    printf("fs tree has %u leaf\n", i);
}

static void init()
{
    crc_init();
    hash_init(inodes_hlist);
}

static void alloc_and_init_inode(struct btrfs_inode_item *inode_item, u64 ino)
{
    struct btrfs_inode *btrfs_inode = malloc(sizeof(*btrfs_inode));
    struct inode *inode = &btrfs_inode->vfs_inode;

    memset(btrfs_inode, 0, sizeof(*btrfs_inode));
    inode->i_ino = ino;
    if (inode->i_ino == BTRFS_ROOT_INO) {
        inode->i_parent = NULL;
        inode->i_name = malloc(2);
        // printf("find root\n");
        memcpy(inode->i_name, "/", 1);
        inode->i_name[1] = '\0';
    }
    INIT_HLIST_NODE(&inode->i_htnode);
    INIT_LIST_HEAD(&inode->i_extents);
    INIT_LIST_HEAD(&inode->i_xattrs);
    hash_add(inodes_hlist, &inode->i_htnode, inode_hash(inode->i_ino));
    inode->i_mode = inode_item->mode;
    inode->i_size = inode_item->size;
    inode->i_uid  = inode_item->uid;
    inode->i_gid  = inode_item->gid;
    inode->i_atime = inode_item->atime;
    inode->i_mtime = inode_item->mtime;
}

static void
get_all_inodes_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_INODE_ITEM_KEY) {
        // type BTRFS_DIR_INDEX_KEY corresponding to struct btrfs_dir_item
        struct btrfs_inode_item *inode_item = (struct btrfs_inode_item*)data_ptr;
        u64 ino = item->key.objectid;

        inodes_num++;
        alloc_and_init_inode(inode_item, ino);
    }
}

static void get_all_inodes(struct btrfs_fs_info *fs_info)
{
    struct node *node;

    list_for_each_entry(node, &fs_info->fs_root->leaf_nodes, list) {
        struct btrfs_leaf *leaf = (struct btrfs_leaf*)node->data;
        btrfs_read_leaf(fs_info, fs_info->fs_root, leaf, get_all_inodes_handler);
    }
}

static void
alloc_and_init_extent(struct btrfs_file_extent_item *extent_item, u64 ino, u64 offset, u64 size)
{
    struct extent *extent = malloc(sizeof(*extent));
    // struct btrfs_file_extent_item *item = malloc(sizeof(*item));
    struct btrfs_file_extent_item *item = extent_item;
    struct inode *inode = get_inode_by_ino(ino);

    check_error(!extent || !item, btrfs_err("oom\n"));
    memset(extent, 0, sizeof(*extent));
    extent->offset = offset;
    extent->size = size;
    INIT_LIST_HEAD(&extent->list);
    extent->extent = item;
    list_add_tail(&extent->list, &inode->i_extents);
}

void get_all_extents_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_EXTENT_DATA_KEY) {
        // type BTRFS_DIR_INDEX_KEY corresponding to struct btrfs_dir_item
        struct btrfs_file_extent_item *extent_item = (struct btrfs_file_extent_item*)data_ptr;
        u64 ino = item->key.objectid;

        alloc_and_init_extent(extent_item, ino, item->key.offset, item->size);
    }
}

static void get_all_extents(struct btrfs_fs_info *fs_info)
{
    struct node *node;

    list_for_each_entry(node, &fs_info->fs_root->leaf_nodes, list) {
        struct btrfs_leaf *leaf = (struct btrfs_leaf*)node->data;
        btrfs_read_leaf(fs_info, fs_info->fs_root, leaf, get_all_extents_handler);
    }
}

static void
alloc_and_init_xattr(struct btrfs_dir_item *di, u64 ino, u64 total_len)
{
    struct inode *inode = get_inode_by_ino(ino);
    u64 cur = 0;

    while (cur < total_len) {
        struct xattr *xattr = malloc(sizeof(*xattr));
        size_t name_len = (size_t)di->name_len;
        size_t value_len = (size_t)di->data_len;
        u64 len = 0;

        check_error(!xattr, btrfs_err("oom\n"));
        xattr->key = malloc(name_len + 1);
        xattr->value = malloc(value_len + 1);
        check_error(!xattr->key || !xattr->value, btrfs_err("oom\n"));

        INIT_LIST_HEAD(&xattr->list);
        memcpy(xattr->key, (char*)(di+1), name_len);
        xattr->key[name_len] = '\0';
        memcpy(xattr->value, (char*)(di+1) + name_len, value_len);
        xattr->value[value_len] = '\0';

        list_add_tail(&xattr->list, &inode->i_xattrs);

        len = sizeof(*di) + name_len + value_len;
        cur += len;
        di = (struct btrfs_dir_item*)((char*)di + len);
    }
}

void get_all_xattrs_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_XATTR_ITEM_KEY) {
        struct btrfs_dir_item *di = (struct btrfs_dir_item*)data_ptr;
        u64 ino = item->key.objectid;

        alloc_and_init_xattr(di, ino, item->size);
    }
}

static void get_all_xattrs(struct btrfs_fs_info *fs_info)
{
    struct node *node;

    list_for_each_entry(node, &fs_info->fs_root->leaf_nodes, list) {
        struct btrfs_leaf *leaf = (struct btrfs_leaf*)node->data;

        btrfs_read_leaf(fs_info, fs_info->fs_root, leaf, get_all_xattrs_handler);
    }
}

static struct inode *get_inode_by_ino(u64 ino)
{
    u64 hash = inode_hash(ino);
    struct hlist_head *hlist = &inodes_hlist[hash_min(hash, BTRFS_HASH_BITS)];
    struct inode *inode = NULL;

    hlist_for_each_entry(inode, hlist, i_htnode) {
        if (inode->i_ino == ino) {
            return inode;
        }
    }

    check_error(1, btrfs_err("cannot find inode for ino:0x%lx\n", ino));
    return NULL;
}

void inode_item_handler(struct btrfs_fs_info *fs_info, struct btrfs_item *item, void *data_ptr)
{
    u32 type = item->key.type;

    if (type == BTRFS_DIR_INDEX_KEY) {
        /* See btrfs_read_locked_inode() */
        struct btrfs_dir_item *dir_item = (struct btrfs_dir_item*)data_ptr;
        u64 ino = dir_item->location.objectid;
        u64 parent_ino = item->key.objectid;
        struct inode *inode = get_inode_by_ino(ino);
        struct inode *parent = get_inode_by_ino(parent_ino);

        inode->i_parent = parent;
        inode->i_type   = dir_item->type;
        inode->i_name = malloc(dir_item->name_len + 1);
        inode->i_name[dir_item->name_len] = '\0';
        memcpy(inode->i_name, (char*)(dir_item+1), dir_item->name_len);
    }
}

static void fill_inodes()
{
    struct node *node;

    list_for_each_entry(node, &fs_info->fs_root->leaf_nodes, list) {
        struct btrfs_leaf *leaf = (struct btrfs_leaf*)node->data;
        btrfs_read_leaf(fs_info, fs_info->fs_root, leaf, inode_item_handler);
    }
}

static void restore_metadata(int fd, struct inode *inode)
{
    struct timespec times[2];

    fchown(fd, inode->i_uid, inode->i_gid);
    fchmod(fd, inode->i_mode);
    times[0].tv_sec = inode->i_atime.sec;
    times[0].tv_nsec = inode->i_atime.nsec;
    times[1].tv_sec = inode->i_mtime.sec;
    times[1].tv_nsec = inode->i_mtime.nsec;
    futimens(fd, times);
}

static void restore_xattrs(int fd, struct inode *inode)
{
    struct xattr *xattr;

    list_for_each_entry(xattr, &inode->i_xattrs, list) {
        fsetxattr(fd, xattr->key, xattr->value, strlen(xattr->value), 0);
    }
}

static ssize_t read_data_from_disk(void *buf, u64 logical,
			u64 len)
{
    u64 physical;
	ssize_t ret;

	physical = btrfs_map_block(fs_info, logical, len);

	ret = pread(fs_info->fd, buf, len, physical);
	if (ret < 0) {
		fprintf(stderr, "Error reading %lu, %lu\n", logical,
			ret);
		return -EIO;
	}
	if (ret != len) {
		fprintf(stderr,
			"Short read for %lu, read %ld, read_len %lu\n",
			logical, ret, len);
		return -EIO;
	}

    return len;
}

static void
copy_one_extent(int fd, struct btrfs_file_extent_item *fi, u64 pos, const char *path)
{
    u64 bytenr;
	u64 ram_size;
	u64 disk_size;
	u64 num_bytes;
	u64 length;
	u64 size_left;
	u64 offset;
	u64 cur;
    size_t total = 0;
	ssize_t ret, done;
    char *inbuf;

	bytenr    = fi->disk_bytenr;
	disk_size = fi->disk_num_bytes;
	ram_size  = fi->ram_bytes;
	offset    = fi->offset;
	num_bytes = fi->num_bytes;
    size_left = disk_size;
	/* Hole, early exit */
	if (disk_size == 0)
		return;

	/* Invalid file extent */
	if (offset >= disk_size || offset > ram_size) {
		btrfs_err(
	"invalid data extent offset, offset %lu disk_size %lu ram_size %lu",
		      offset, disk_size, ram_size);
        return;
	}

	if (offset < disk_size) {
		bytenr += offset;
		size_left -= offset;
	}

    inbuf = malloc(size_left);
    check_error(!inbuf, btrfs_err("oom\n"));

    cur = bytenr;
    while (cur < bytenr + size_left) {
		length = bytenr + size_left - cur;
		ret = read_data_from_disk(inbuf + cur - bytenr, cur, length);
		if (ret < 0) {
			return;
		}
		cur += length;
	}

    while (total < num_bytes) {
        done = pwrite(fd, inbuf+total, num_bytes-total,
                    pos+total);
        if (done < 0) {
            btrfs_err("cannot write data: %d %m file %s fd %d\n", errno, path, fd);
            free(inbuf);
            return;
        }
        total += done;
    }

    free(inbuf);
}

static void restore_data(int fd, struct inode *inode, const char *path)
{
    struct extent *extent;
    struct btrfs_file_extent_item *fi;

    list_for_each_entry(extent, &inode->i_extents, list) {
        fi = extent->extent;

        if (fi->compression != BTRFS_COMPRESS_NONE) {
            btrfs_err("don't support compression yet\n");
            return;
        }

        if (fi->type == BTRFS_FILE_EXTENT_PREALLOC) {
            continue;
        }

        if (fi->type == BTRFS_FILE_EXTENT_INLINE) {
            pwrite(fd,  btrfs_file_extent_inline_start(fi),
                fi->ram_bytes, extent->offset);
        } else if (fi->type == BTRFS_FILE_EXTENT_REG) {
            copy_one_extent(fd, fi, extent->offset, path);
        } else {
            btrfs_err("weird extent type:%d for file %s\n", fi->type, path);
        }
    }

    ftruncate(fd, inode->i_size);
}

static void restore_symlink(struct inode *inode, const char *path)
{
    struct extent *extent;
    struct btrfs_file_extent_item *fi;

    list_for_each_entry(extent, &inode->i_extents, list) {
        char *start;
        u64 len;
        char *target;

        fi = extent->extent;
        start = (char*)fi + offsetof(struct btrfs_file_extent_item, disk_bytenr);
        len = extent->size - BTRFS_FILE_EXTENT_INLINE_DATA_START;
        target = malloc(len + 1);
        check_error(!target, perror("malloc"));
        memcpy(target, start, len);
        target[len] = '\0';
        if (symlink(target, path)) {
            perror("symlink");
        }

        free(target);
    }
}

static void rebuild_fs_tree(struct inode *dir, const char *name)
{
    check_error(!S_ISDIR(dir->i_mode), btrfs_err("not directort\n"));
    u64 i = 0;
    struct inode *inode = NULL;
    char *path = malloc(4096);

    hash_for_each(inodes_hlist, i, inode, i_htnode) {
        /* skip other inodes */
        if (inode->i_parent != dir) {
            continue;
        }
        memset(path, 0, MAX_PATH_LEN);
        strcpy(path, name);
        strcat(path, "/");
        strcat(path, inode->i_name);

        if (S_ISDIR(inode->i_mode)) {
            check_error(mkdir(path, 0755),
                {perror("mkdir"); printf("path is %s\n", path);});
            rebuild_fs_tree(inode, path);
        } else if (S_ISREG(inode->i_mode)) {
            int fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0666);
            check_error(fd == -1,
                {perror("open"); printf("path is %s, ret: %d\n", path, fd);});
            restore_data(fd, inode, path);
            restore_metadata(fd, inode);
            restore_xattrs(fd, inode);
            check_error(close(fd), perror("close"));
        } else if (S_ISLNK(inode->i_mode)) {
            restore_symlink(inode, path);
        }
    }

    free(path);
}

static void walk_fs(struct btrfs_fs_info *fs_info)
{
    struct inode *root = NULL;

    get_all_inodes(fs_info);
    fill_inodes();
    get_all_extents(fs_info);
    get_all_xattrs(fs_info);
    root = get_inode_by_ino(BTRFS_ROOT_INO);
    rebuild_fs_tree(root, restore_path);
}

int main (int argc, char **argv)
{
    struct btrfs_super_block btrfs_sb;

    check_error(argc != 3, printf("USAGE: %s $btrfs_img $restore_path\n", argv[0]));
    restore_path = argv[2];
    init();

    if (access(restore_path, R_OK|W_OK)) {
        check_error(1, perror("access"));
    }
    fs_info = malloc(sizeof(*fs_info));
    check_error(!fs_info, btrfs_err("oom\n"));

    fs_info->fd = btrfs_read_sb(&btrfs_sb, argv[1]);
    fs_info->btrfs_sb = &btrfs_sb;
    fs_info->mapping_tree = RB_ROOT_CACHED;

    fs_info->chunk_root = btrfs_alloc_root();
    fs_info->fs_root = btrfs_alloc_root();
    fs_info->roots = btrfs_alloc_root();

    btrfs_read_sys_chunk(fs_info);
    btrfs_read_chunk_tree(fs_info);
    // The root tree
    btrfs_read_root_tree(fs_info);
    btrfs_read_fs_tree(fs_info);
    walk_fs(fs_info);

    // show_result();
    return 0;
}
#ifndef _VFS_H
#define _VFS_H
#include "types.h"
#include "btrfs_tree.h"


// #define S_IFMT  00170000
// #define S_IFSOCK 0140000
// #define S_IFLNK	 0120000
// #define S_IFREG  0100000
// #define S_IFBLK  0060000
// #define S_IFDIR  0040000
// #define S_IFCHR  0020000
// #define S_IFIFO  0010000
// #define S_ISUID  0004000
// #define S_ISGID  0002000
// #define S_ISVTX  0001000

// #define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
// #define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
// #define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
// #define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
// #define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
// #define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
// #define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

struct inode {
	unsigned long		    i_ino;
	u64			            i_size;
    char *                  i_name;
    struct hlist_node       i_htnode;
    struct list_head        i_extents;
    struct list_head        i_xattrs;

    u32                     i_mode;     // from inode item
    u8                      i_type;     // from index dir item
    struct inode *          i_parent;
    u32                     i_uid;
	u32                     i_gid;
    struct btrfs_timespec   i_atime;
	struct btrfs_timespec   i_mtime;
};

struct btrfs_file_extent_item;
struct extent {
    struct list_head list;
    struct btrfs_file_extent_item *extent;
    u64 offset;     // for regular file offset
    u64 size;       // for symlink
};

struct xattr {
    char *key;
    char *value;

    struct list_head list;
};

#endif
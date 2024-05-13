#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    fprintf(stderr, "func: %s line: %u\t\t" fmt, __func__, __LINE__, ##args);   \
} while(0)

typedef __s8  s8;
typedef __u8  u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

void btrfs_read_sb(struct btrfs_super_block *btrfs_sb, const char *img_name)
{
    int fd;
    int ret;

    fd = open(img_name, O_RDONLY);
    check_error(fd == -1, perror("open"));
    ret = pread(fd, btrfs_sb, sizeof(struct btrfs_super_block), BTRFS_SUPER_INFO_OFFSET);
    check_error(ret != sizeof(struct btrfs_super_block), perror("read"));
    check_error(btrfs_sb->magic != BTRFS_MAGIC, btrfs_err("bad magic number\n"));
}

int main (int argc, char **argv)
{
    struct btrfs_super_block btrfs_sb;
    check_error(argc != 2, printf("USAGE: %s $btrfs_img\n", argv[0]));
    btrfs_read_sb(&btrfs_sb, argv[1]);
    return 0;
}
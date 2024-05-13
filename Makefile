OBJS=btrfs_internal.o rbtree/rbtree.o
CC=gcc
CFLAGS=-ggdb

btrfs_i: Makefile $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o ./btrfs_i

clean:
	rm -f ./*.o ./rbtree/*.o btrfs_i
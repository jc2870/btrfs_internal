OBJS=btrfs_internal.o rbtree/rbtree.o
CC=gcc

btrfs_i: Makefile $(OBJS)
	$(CC) $(OBJS) -o ./btrfs_i

clean:
	rm -f ./*.o ./rbtree/*.o btrfs_i

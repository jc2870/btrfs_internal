#ifndef _LIB_H
#define _LIB_H

#include "types.h"
uint32_t crc32(const uint8_t* buffer, size_t len);
uint64_t crc64(const void* buffer, size_t len);
void crc_init();

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static __always_inline int fls(unsigned int x)
{
	int r;

	/*
	 * AMD64 says BSRL won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before, except that the
	 * top 32 bits will be cleared.
	 *
	 * We cannot do this on 32 bits because at the very least some
	 * 486 CPUs did not behave this way.
	 */
	asm("bsrl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));

	return r + 1;
}

static __always_inline int fls64(u64 x)
{
	int bitpos = -1;
	/*
	 * AMD64 says BSRQ won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before.
	 */
	asm("bsrq %1,%q0"
	    : "+r" (bitpos)
	    : "rm" (x));
	return bitpos + 1;
}

static inline __attribute__((const))
int __ilog2_u32(u32 n)
{
	return fls(n) - 1;
}

static inline __attribute__((const))
int __ilog2_u64(u64 n)
{
	return fls64(n) - 1;
}

#define ilog2(n) \
( \
	(sizeof(n) <= 4) ?		\
	__ilog2_u32(n) :		\
	__ilog2_u64(n)			\
 )


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define HASH_SIZE(name) (ARRAY_SIZE(name))
#define HASH_BITS(name) ilog2(HASH_SIZE(name))

static inline u32 __hash_32_generic(u32 val)
{
	return val * GOLDEN_RATIO_32;
}

static inline u32 hash_32_generic(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32_generic(val) >> (32 - bits);
}

static __always_inline u32 hash_64_generic(u64 val, unsigned int bits)
{
    if (sizeof(void*) == 8)
        /* 64x64-bit multiply is efficient on all 64-bit processors */
        return val * GOLDEN_RATIO_64 >> (64 - bits);
    else
        /* Hash 64 bits using only 32x32-bit multiply. */
        return hash_32_generic((u32)val ^ __hash_32_generic(val >> 32), bits);
}

/* Use hash_32 when possible to allow for fast 32bit hashing in 64bit kernels. */
#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32_generic(val, bits) : hash_64_generic(val, bits))

static inline void __hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

/**
 * hash_init - initialize a hash table
 * @hashtable: hashtable to be initialized
 *
 * Calculates the size of the hashtable from the given parameter, otherwise
 * same as hash_init_size.
 *
 * This has to be a macro since HASH_BITS() will not work on pointers since
 * it calculates the size during preprocessing.
 */
#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))

/**
 * hash_add - add an object to a hashtable
 * @hashtable: hashtable to add to
 * @node: the &struct hlist_node of the object to be added
 * @key: the key of the object to be added
 */
#define hash_add(hashtable, node, key)						\
	hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])


#endif
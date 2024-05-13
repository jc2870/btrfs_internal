#ifndef _TYPE_H
#define _TYPE_H

#include <inttypes.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t  s8;

typedef u64 refcount_t;

struct list_head {
	struct list_head *next, *prev;
};

#endif
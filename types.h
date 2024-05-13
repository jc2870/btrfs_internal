#ifndef _TYPE_H
#define _TYPE_H

#include <inttypes.h>
#include <stdio.h>

#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t  s8;

#define bool char
#define true 1
#define false 0

typedef u64 refcount_t;
struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

typedef struct {
	u32 val;
} kuid_t;

typedef struct {
	u32 val;
} kgid_t;

struct timespec64 {
	s64	tv_sec;			/* seconds */
	long		tv_nsec;		/* nanoseconds */
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);
	WRITE_ONCE(list->prev, list);
}

/*
 * Insert a _new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *_new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	WRITE_ONCE(prev->next, _new);
}

/**
 * list_add - add a _new entry
 * @_new: _new entry to be added
 * @head: list head to add it after
 *
 * Insert a _new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head, head->next);
}


/**
 * list_add_tail - add a _new entry
 * @_new: _new entry to be added
 * @head: list head to add it before
 *
 * Insert a _new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head->prev, head);
}

static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

/**
 * hlist_unhashed - Has node been removed from list and reinitialized?
 * @h: Node to be checked
 *
 * Not that not all removal functions will leave a node in unhashed
 * state.  For example, hlist_nulls_del_init_rcu() does leave the
 * node in unhashed state, but hlist_nulls_del() does not.
 */
static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

/**
 * hlist_unhashed_lockless - Version of hlist_unhashed for lockless use
 * @h: Node to be checked
 *
 * This variant of hlist_unhashed() must be used in lockless contexts
 * to avoid potential load-tearing.  The READ_ONCE() is paired with the
 * various WRITE_ONCE() in hlist helpers that are defined below.
 */
static inline int hlist_unhashed_lockless(const struct hlist_node *h)
{
	return !READ_ONCE(h->pprev);
}

/**
 * hlist_empty - Is the specified hlist_head structure an empty hlist?
 * @h: Structure to check.
 */
static inline int hlist_empty(const struct hlist_head *h)
{
	return !READ_ONCE(h->first);
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	WRITE_ONCE(*pprev, next);
	if (next)
		WRITE_ONCE(next->pprev, pprev);
}

/**
 * hlist_del - Delete the specified hlist_node from its list
 * @n: Node to delete.
 *
 * Note that this function leaves the node in hashed state.  Use
 * hlist_del_init() or similar instead to unhash @n.
 */
static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = NULL;
	n->pprev = NULL;
}

/**
 * hlist_del_init - Delete the specified hlist_node from its list and initialize
 * @n: Node to delete.
 *
 * Note that this function leaves the node in unhashed state.
 */
static inline void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

/**
 * hlist_add_head - add a new entry at the beginning of the hlist
 * @n: new entry to be added
 * @h: hlist head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	WRITE_ONCE(n->next, first);
	if (first)
		WRITE_ONCE(first->pprev, &n->next);
	WRITE_ONCE(h->first, n);
	WRITE_ONCE(n->pprev, &h->first);
}

/**
 * hlist_add_before - add a new entry before the one specified
 * @n: new entry to be added
 * @next: hlist node to add it before, which must be non-NULL
 */
static inline void hlist_add_before(struct hlist_node *n,
				    struct hlist_node *next)
{
	WRITE_ONCE(n->pprev, next->pprev);
	WRITE_ONCE(n->next, next);
	WRITE_ONCE(next->pprev, &n->next);
	WRITE_ONCE(*(n->pprev), n);
}

/**
 * hlist_add_behind - add a new entry after the one specified
 * @n: new entry to be added
 * @prev: hlist node to add it after, which must be non-NULL
 */
static inline void hlist_add_behind(struct hlist_node *n,
				    struct hlist_node *prev)
{
	WRITE_ONCE(n->next, prev->next);
	WRITE_ONCE(prev->next, n);
	WRITE_ONCE(n->pprev, &prev->next);

	if (n->next)
		WRITE_ONCE(n->next->pprev, &n->next);
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#define hash_for_each(name, bkt, obj, member)				\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry(obj, &name[bkt], member)

#endif
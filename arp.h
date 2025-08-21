#ifndef __ARP_H__
#define __ARP_H__

#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <string.h>

#define ARP_ENTRY_STATIC_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1

/* Linked list macros with improved safety */
#define LL_ADD(item, list) do {				\
		(item)->prev = NULL;				\
		(item)->next = (list);				\
		if ((list) != NULL) {				\
			(list)->prev = (item);			\
		}									\
		(list) = (item);					\
	} while (0)

#define LL_REMOVE(item, list) do {							\
		if ((item)->prev != NULL) {							\
			(item)->prev->next = (item)->next;				\
		}													\
		if ((item)->next != NULL) {							\
			(item)->next->prev = (item)->prev;				\
		}													\
		if ((list) == (item)) {								\
			(list) = (item)->next;							\
		}													\
		(item)->prev = (item)->next = NULL;					\
	} while (0)

struct arp_entry {
	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
	uint8_t status;
	
	struct arp_entry *next;
	struct arp_entry *prev;
};

struct arp_table {
	struct arp_entry *entries;
	int count;
};

static struct arp_table *g_arpt = NULL;

static struct arp_table *
arp_table_instance(void) 
{
	if (g_arpt == NULL) {
		g_arpt = rte_malloc("arp_table", sizeof(struct arp_table), 0);
		if (g_arpt == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to allocate ARP table\n");
		}
		memset(g_arpt, 0, sizeof(struct arp_table));
	}
	return g_arpt;
}

static uint8_t* 
get_dst_macaddr(uint32_t dip) 
{
	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries; iter != NULL; iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}

	return NULL;
}

/* Clean up ARP table - useful for graceful shutdown */
static void
arp_table_cleanup(void)
{
	if (g_arpt != NULL) {
		struct arp_entry *entry = g_arpt->entries;
		while (entry != NULL) {
			struct arp_entry *next = entry->next;
			rte_free(entry);
			entry = next;
		}
		rte_free(g_arpt);
		g_arpt = NULL;
	}
}

#endif /* __ARP_H__ */
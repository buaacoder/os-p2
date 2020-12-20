#include "swap.h"
#include "devices/block.h"
#include <debug.h>

#include <list.h>

static struct list swap_slot_list;
struct block *global_swap_block;

void init_swap() {
    global_swap_block = block_get_role(BLOCK_SWAP);
    list_init(&swap_slot_list);
}

block_sector_t get_swap_slot() {
    // maybe bug here
    block_sector_t index = -1;
    if (list_empty(&swap_slot_list))
        PANIC("no free swap slot");

    struct list_elem *elem = list_pop_front(&swap_slot_list);
    struct swap_slot *slot = list_entry(elem, struct swap_slot, list_elem);
    index = slot->index;
    free(slot);
    return index;
}

block_sector_t write_swap(void *kpage) {
    block_sector_t index = get_swap_slot();
    for (int i = 0; i < 8; i++)
        block_write(global_swap_block, index + i,
                    kpage + i * BLOCK_SECTOR_SIZE);
    return index;
}

void read_swap(void *kpage, block_sector_t index) {
    for (int i = 0; i < 8; i++) {
        block_read(global_swap_block, index + i, kpage + i * BLOCK_SECTOR_SIZE);
    }
    free_swap(index);
}

void free_swap(block_sector_t index) {
    struct swap_slot *slot =
        (struct swap_slot *)malloc(sizeof(struct swap_slot));
    slot->index = index;
    list_push_back(&swap_slot_list, &(slot->list_elem));
}
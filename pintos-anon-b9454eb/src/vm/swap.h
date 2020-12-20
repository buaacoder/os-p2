#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include <list.h>

struct swap_slot {
    block_sector_t index;
    struct list_elem list_elem;
};

void init_swap();
block_sector_t get_swap_slot();
block_sector_t write_swap(void *kpage);
void read_swap(void *kpage, block_sector_t index);
void free_swap(block_sector_t index);

#endif // VM_SWAP_H
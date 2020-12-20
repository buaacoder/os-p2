#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "threads/palloc.h"
#include "page.h"
#include <list.h>
#include <stdbool.h>

struct frame_table_entry {
    void *kpage;
    void *upage;
    struct thread *owner;
    struct list_elem list_elem;
    struct hash_elem hash_elem;
    bool is_pinned;
};

unsigned frame_hash_func(const struct hash_elem *elem);
bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b);

struct frame_table_entry *next_frame(struct frame_table_entry *fte);

void *get_frame(void *upage, enum palloc_flags flag);
void *get_used_frame(void *upage);
void free_frame(void *kpage); 
void *find_frame(void *kpage);
bool unpin_frame(void *kpage);

void grow_stack(void *vaddr, struct page_table_entry *pte);

#endif // VM_FRAME_H
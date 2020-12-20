#include "devices/timer.h"

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#include <list.h>
#include <stdlib.h>

#include "frame.h"
#include "page.h"
#include "swap.h"

static struct list frame_clock_table;
static struct hash frame_table;

struct frame_table_entry *evict;

unsigned frame_hash_func(const struct hash_elem *elem) {
    struct frame_table_entry *fte =
        hash_entry(elem, struct frame_table_entry, hash_elem);
    return hash_bytes(&(fte->kpage), sizeof(fte->kpage));
}

bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b) {
    struct frame_table_entry *fte_a =
        hash_entry(a, struct frame_table_entry, hash_elem);
    struct frame_table_entry *fte_b =
        hash_entry(b, struct frame_table_entry, hash_elem);
    return fte_a->kpage < fte_b->kpage;
}

void init_frame_table() {
    list_init(&frame_clock_table);
    hash_init(&frame_table, frame_hash_func, frame_less_func, NULL);
    evict = NULL;
}

void *get_frame(void *upage, enum palloc_flags flag) {

    void *kpage = palloc_get_page(PAL_USER | flag);

    if (kpage == NULL) {
        kpage = get_used_frame(upage);
        if (flag == PAL_ZERO)
            memset(kpage, 0, PGSIZE);
        if (flag == PAL_ASSERT)
            PANIC("Frame: Run out of pages.\n");
    }

    struct frame_table_entry *fte =
        (struct frame_table_entry *)malloc(sizeof(struct frame_table_entry));
    fte->kpage = kpage;
    fte->upage = upage;
    fte->owner = thread_current();
    fte->is_pinned = true;

    hash_insert(&frame_table, &(fte->hash_elem));
    return kpage;
}

void *get_used_frame(void *upage) {
    while (pagedir_is_accessed(evict->owner->pagedir, evict->upage)) {
        pagedir_set_accessed(evict->owner->pagedir, evict->upage, false);
        evict = next_frame(evict);
    }

    struct thread *cur = thread_current();
    struct frame_table_entry *fte = evict;
    void *kpage = fte->kpage;
    struct page_table_entry *pte =
        find_page(evict->owner->sup_page_table, evict->upage);

    bool success = false;
    if (pte == NULL || pte->mmapinfo->file == NULL) {
        block_sector_t index = write_swap(evict->kpage);
        if (pte->status == IN_FRAME) {
            pte->swapid = index;
            pte->status = IN_SWAP;
            pagedir_clear_page(cur->pagedir, upage);
            success = true;
        }
    } else {
        // TODO mmap_write_file
        if (pte->status == IN_FRAME) {
            pte->status = IN_FILE;
        }
    }

    if (!success)
        return false;

    list_remove(&(fte->list_elem));
    if (list_empty(&frame_clock_table))
        evict = NULL;
    else
        evict = next_frame(evict);

    hash_delete(&frame_table, &(fte->hash_elem));
    free(fte);
    return kpage;
}

void free_frame(void *kpage) {
    struct frame_table_entry *fte = find_frame(kpage);
    if (fte == NULL)
        return;

    // printf("start check pin\n");
    if (!fte->is_pinned) {
        // printf("start evict\n");
        if (fte == evict) {
            evict = next_frame(evict);
            // printf("end next\n");
        }
        // printf("not evict\n");

        list_remove(&(fte->list_elem));
        // printf("end list_remove\n");
    }

    hash_delete(&frame_table, &(fte->hash_elem));
    free(fte);
    palloc_free_page(kpage);
}

void *find_frame(void *kpage) {
    struct hash_elem *elem;
    struct frame_table_entry *fte =
        (struct frame_table_entry *)malloc(sizeof(struct frame_table_entry));
    fte->kpage = kpage;
    elem = hash_find(&frame_table, &(fte->hash_elem));
    if (elem)
        return hash_entry(elem, struct frame_table_entry, hash_elem);
    return NULL;
}

bool unpin_frame(void *kpage) {
    struct frame_table_entry *fte = find_frame(kpage);
    if (fte == NULL)
        return false;
    if (fte->is_pinned == false)
        return true;

    fte->is_pinned = false;
    list_push_back(&frame_clock_table, &(fte->list_elem));
    if (list_size(&frame_clock_table) == 1)
        evict = fte;
    return true;
}

struct frame_table_entry *next_frame(struct frame_table_entry *fte) {
    if (list_empty(&frame_clock_table))
        return NULL;
    if (list_size(&frame_clock_table) == 1)
        return fte;

    if (&(fte->list_elem) == list_back(&frame_clock_table))
        fte = list_entry(list_head(&frame_clock_table),
                         struct frame_table_entry, list_elem);
    fte = list_entry(list_next(&(fte->list_elem)), struct frame_table_entry,
                     list_elem);
    return fte;
}

struct frame_table_entry *prev_frame(struct frame_table_entry *fte) {
    // if (list_size(&frame_clock_table) == 1)
    //     return;
    // if (&(fte->list_elem) == list_front(&frame_clock_table))
    //     fte = list_entry(list_tail(&frame_clock_table),
    //                      struct frame_table_entry, list_elem);
    // fte = list_entry(list_prev(&(fte->list_elem)), struct frame_table_entry,
    //                  list_elem);
    // return fte;
    return NULL;
}
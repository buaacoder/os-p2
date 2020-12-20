#include "devices/timer.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#include "frame.h"
#include "page.h"
#include "swap.h"

#include <hash.h>
#include <stdlib.h>

void init_page_mutex() { lock_init(&page_mutex); }

unsigned page_hash_func(const struct hash_elem *elem) {
    struct page_table_entry *pte =
        hash_entry(elem, struct page_table_entry, hash_elem);
    return hash_bytes(&(pte->vaddr), sizeof(pte->vaddr));
}

bool page_less_func(const struct hash_elem *a, const struct hash_elem *b) {
    struct page_table_entry *pte_a =
        hash_entry(a, struct page_table_entry, hash_elem);
    struct page_table_entry *pte_b =
        hash_entry(b, struct page_table_entry, hash_elem);
    return pte_a->vaddr < pte_b->vaddr;
}

void page_destroy_func(struct hash_elem *elem) {
    struct page_table_entry *pte =
        hash_entry(elem, struct page_table_entry, hash_elem);
    if (pte->status = IN_FRAME) {
        pagedir_clear_page(thread_current()->pagedir, pte->vaddr);
        free_frame(pte->paddr);
    }
    free(pte);
}

struct hash *create_page_table() {
    struct hash *page_table = (struct hash *)malloc(sizeof(struct hash));

    if (page_table) {
        if (hash_init(page_table, page_hash_func, page_less_func, NULL)) {
            return page_table;
        }
        free(page_table);
    }
    return NULL;
}

void destroy_page_table(struct hash *page_table) {
    lock_acquire(&page_mutex);
    hash_destroy(page_table, page_destroy_func);
    free(page_table);
    lock_release(&page_mutex);
}

struct page_table_entry *find_page(struct hash *page_table, void *upage) {
    // lock_acquire(&page_mutex);
    struct hash_elem *elem;
    struct page_table_entry *pte =
        (struct page_table_entry *)malloc(sizeof(struct page_table_entry));
    pte->vaddr = upage;
    elem = hash_find(page_table, &(pte->hash_elem));

    if (elem)
        pte = hash_entry(elem, struct page_table_entry, hash_elem);
    else
        pte = NULL;

    // lock_release(&page_mutex);
    return pte;
}

bool handle_fault(void *vaddr, bool write, void *esp) {
    struct thread *t = thread_current();
    struct hash *page_table = t->sup_page_table;
    uint32_t *pagedir = t->pagedir;
    void *upage = pg_round_down(vaddr);
    void *kpage = NULL;
    struct page_table_entry *pte = find_page(page_table, upage);

    if (write && pte != NULL && pte->writable == false)
        return false;

    bool success = false;
    lock_acquire(&page_mutex);

    if (upage >= PHYS_BASE - 0x800000 && vaddr >= esp - 32) {
        if (pte == NULL) {
            kpage = get_frame(upage, 0);
            if (kpage) {
                pte = (struct page_table_entry *)malloc(
                    sizeof(struct page_table_entry));
                pte->vaddr = upage;
                pte->paddr = kpage;
                pte->status = IN_FRAME;
                pte->writable = true;
                success = true;
                hash_insert(page_table, &(pte->hash_elem));
            }
        } else if (pte->status == IN_SWAP) {
            kpage = get_frame(upage, 0);
            read_swap(kpage, pte->swapid);
            pte->paddr = kpage;
            pte->status = IN_FRAME;
            success = true;
        }
    } else if (pte) {
        kpage = get_frame(upage, 0);
        if (kpage == NULL) {
            success = false;
            goto end;
        }
        switch (pte->status) {
        case IN_SWAP:
            read_swap(kpage, pte->swapid);
            pte->paddr = kpage;
            pte->status = IN_FRAME;
            success = true;
            break;
        case IN_FILE:
            mmap_read_file(pte->mmapinfo, upage, kpage);
            pte->paddr = kpage;
            pte->status = IN_FRAME;
            success = true;
            break;

        default:
            break;
        }
    }

end:
    unpin_frame(kpage);
    if (success)
        pagedir_set_page(pagedir, pte->vaddr, pte->paddr, pte->writable);
    lock_release(&page_mutex);

    return success;
}

bool check_user_buffer(char *str, int size, bool write) {
    if (!translate_vaddr(str + size - 1, write))
        return false;
    size >>= 12;
    do {
        if (!translate_vaddr(str, write))
            return false;
        str += 1 << 12;

    } while (size--);
    return true;
}

bool translate_vaddr(void *vaddr, bool write) {
    if (vaddr == NULL || !is_user_vaddr(vaddr))
        return false;
    // lock_acquire(&page_mutex);
    struct thread *cur = thread_current();
    struct page_table_entry *pte =
        find_page(cur->sup_page_table, pg_round_down(vaddr));
    bool valid = false;
    if (pte == NULL) {
        valid = handle_fault(vaddr, write, cur->esp);
    } else {
        valid = !(write && !(pte->writable));
    }
    // lock_release(&page_mutex);
    return valid;
}

bool mmap_install_page(struct thread *cur, struct mmap_info *mmapinfo) {
    bool success = true;
    for (int i = 0; i < mmapinfo->use_page_num; i++)
        if (!install_file(cur->sup_page_table, mmapinfo,
                          mmapinfo->vaddr + i * PGSIZE))
            success = false;

    if (mmapinfo->is_load_segment) {
        for (int i = mmapinfo->use_page_num; i < mmapinfo->page_num; i++)
            if (!install_file(cur->sup_page_table, mmapinfo,
                              mmapinfo->vaddr + i * PGSIZE))
                success = false;
    }
    return success;
}

void mmap_read_file(struct mmap_info *mmapinfo, void *upage, void *kpage) {
    if (mmapinfo->is_load_segment) {
        void *vaddr = mmapinfo->vaddr + mmapinfo->use_page_num * PGSIZE +
                      mmapinfo->last_page;
        vaddr -= PGSIZE * (mmapinfo->last_page != 0);

        if (vaddr > upage) {
            off_t size =
                (vaddr - upage < PGSIZE) ? mmapinfo->last_page : PGSIZE;
            file_read_at(mmapinfo->file, kpage, size,
                         upage - mmapinfo->vaddr + mmapinfo->offset);
            if (size != PGSIZE)
                memset(kpage + mmapinfo->last_page, 0,
                       PGSIZE - mmapinfo->last_page);
        } else
            memset(kpage, 0, PGSIZE);
    } else {
        off_t size =
            (mmapinfo->vaddr + file_length(mmapinfo->file) - upage < PGSIZE)
                ? mmapinfo->last_page
                : PGSIZE;
        file_read_at(mmapinfo->file, kpage, size,
                     upage - mmapinfo->vaddr + mmapinfo->offset);
        if (size != PGSIZE)
            memset(kpage + mmapinfo->last_page, 0,
                   PGSIZE - mmapinfo->last_page);
    }
}

void mmap_write_file(struct mmap_info *mmapinfo, void *upage, void *kpage) {
    if (!mmapinfo->writable)
        return;
    if (mmapinfo->is_load_segment) {
        void *vaddr = mmapinfo->vaddr + mmapinfo->use_page_num * PGSIZE +
                      mmapinfo->last_page;
        if (vaddr > upage) {
            off_t size =
                (vaddr - upage < PGSIZE) ? mmapinfo->last_page : PGSIZE;
            file_write_at(mmapinfo->file, kpage, size,
                          upage - mmapinfo->vaddr + mmapinfo->offset);
        }
    } else {
        off_t size =
            (mmapinfo->vaddr + file_length(mmapinfo->file) - upage < PGSIZE)
                ? mmapinfo->last_page
                : PGSIZE;
        file_write_at(mmapinfo->file, kpage, size,
                      upage - mmapinfo->vaddr + mmapinfo->offset);
    }
}

bool install_file(struct hash *page_table, struct mmap_info *mmapinfo,
                  void *vaddr) {
    struct thread *cur = thread_current();
    lock_acquire(&page_mutex);
    bool success = false;
    if (vaddr < PHYS_BASE - 0x800000 && find_page(page_table, vaddr) == NULL) {
        struct page_table_entry *pte =
            (struct page_table_entry *)malloc(sizeof(struct page_table_entry));
        pte->vaddr = vaddr;
        pte->mmapinfo = mmapinfo;
        pte->status = IN_FILE;
        pte->writable = mmapinfo->writable;
        pte->paddr = mmapinfo;
        hash_insert(page_table, &(pte->hash_elem));
        success = true;
    }
    lock_release(&page_mutex);
    return success;
}

bool uninstall_file(struct hash *page_table, void *addr) {
    struct thread *cur = thread_current();
    struct page_table_entry *pte = find_page(page_table, addr);
    bool success = false;
    // lock_acquire(&page_mutex);
    if (!(addr < PHYS_BASE - 0x800000 && pte != NULL))
        return false;
    switch (pte->status) {
    case IN_FRAME:
        hash_delete(page_table, &(pte->hash_elem));
        free(pte);
        success = true;
        break;

    case IN_FILE:
        if (pagedir_is_dirty(cur->pagedir, pte->vaddr)) {
            mmap_write_file(pte->mmapinfo, pte->vaddr, pte->paddr);
        }
        pagedir_clear_page(cur->pagedir, pte->vaddr);
        hash_delete(page_table, &(pte->hash_elem));
        free_frame(pte->paddr);
        free(pte);
        success = true;
        break;

    default:
        break;
    }
    // lock_release(&page_mutex);
    return success;
}
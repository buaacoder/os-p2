#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "devices/block.h"
#include "filesys/file.h"
#include "filesys/off_t.h"

#include <hash.h>
#include <list.h>
#include <stdbool.h>

enum page_status { IN_FILE, IN_FRAME, IN_SWAP };

struct mmap_info {
    mapid_t mapid;
    struct file *file;
    void *vaddr;
    bool writable;
    off_t offset;
    struct list_elem list_elem;

    int use_page_num;
    int last_page;
    int page_num;
    bool is_load_segment;
    bool is_static_data;
};

struct page_table_entry {
    void *vaddr;
    void *paddr;
    block_sector_t swapid;
    struct mmap_info *mmapinfo;
    bool writable;

    bool dirty;
    bool accessed;

    enum page_status status;

    struct hash_elem hash_elem;
};

static struct lock page_mutex;

void init_page_mutex();
unsigned page_hash_func(const struct hash_elem *elem);
bool page_less_func(const struct hash_elem *a, const struct hash_elem *b);
void page_destroy_func(struct hash_elem *elem);
struct hash *create_page_table();
void destroy_page_table(struct hash *page_table);

struct page_table_entry *find_page(struct hash *page_table, void *upage);
bool handle_fault(void *vaddr, bool write, void *esp);
bool check_user_buffer(char *str, int size, bool write);
bool translate_vaddr(void *vaddr, bool write);

bool mmap_install_page(struct thread *cur, struct mmap_info *mmapinfo);
void mmap_read_file(struct mmap_info *mmapinfo, void *upage, void *kpage);
void mmap_write_file(struct mmap_info *mmapinfo, void *upage, void *kpage);
bool install_file(struct hash *page_table, struct mmap_info *mmapinfo,
                  void *vaddr);
bool uninstall_file(struct hash *page_table, void *vaddr);
#endif // VM_PAGE_H

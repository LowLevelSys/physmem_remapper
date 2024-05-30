#pragma once
#include "../project_includes.hpp"

constexpr uint64_t TABLE_COUNT = 50;
constexpr uint64_t REMAPPING_COUNT = 50;

typedef union {
    struct {
        uint64_t reserved1 : 3;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t reserved2 : 7;
        uint64_t address_of_page_directory : 36;
        uint64_t reserved3 : 16;
    };

    uint64_t flags;
} cr3;

typedef union
{
    struct {
        uint64_t task_priority_level : 4;
        uint64_t reserved : 60;
    };

    uint64_t flags;
} cr8;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t must_be_zero : 1;
        uint64_t ignored_1 : 4;
        uint64_t page_frame_number : 36;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pml4e_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t pat : 1;
        uint64_t reserved1 : 17;
        uint64_t page_frame_number : 18;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pdpte_1gb_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 4;
        uint64_t page_frame_number : 36;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pdpte_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t pat : 1;
        uint64_t reserved1 : 8;
        uint64_t page_frame_number : 27;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pde_2mb_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 4;
        uint64_t page_frame_number : 36;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pde_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t pat : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t page_frame_number : 36;
        uint64_t reserved1 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pte_64;

typedef union {

    struct {
        uint64_t offset_1gb : 30;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_2mb : 21;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_4kb : 12;
        uint64_t pte_idx : 9;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    uint64_t flags;
} va_64;

struct slot_t {
    void* table;
    bool large_page;
};

struct remapped_entry_t {
    va_64 remapped_va;

    // Pml4 slot not needed as we only have 1 anyways
    slot_t pdpt_table;
    slot_t pd_table;
    void* pt_table;

    bool used;
};

enum usable_until {
    pdpt_table_valid, // Means that the pml4 at the correct index already points to a remapped pdpt table
    pde_table_valid,  // Means that the pdpt at the correct index already points to a remapped pde table
    pte_table_valid,  // Means that the pde at the correct index already points to a remapped pte table
    non_valid,        // Means that the pml4 indexes didn't match
};

enum restorable_until {
    pdpt_table_removeable, // You can free everything up to the pdpt table
    pde_table_removeable, // You can free everything up to the pde level
    pte_table_removeable, // You can free everything up to the pte level
    nothing_removeable,    // You can free nothing as there is another mapping in the remapped pte table
};

struct constructed_page_tables {
    // We copy the top layer of pml4's and insert a new entry for memory copying util
    pml4e_64* pml4_table;

    // These are here for remapping
    union {
        pdpte_64* pdpt_table[TABLE_COUNT];
        pdpte_1gb_64* pdpt_1gb_table[TABLE_COUNT];
    };
    union {
        pde_64* pd_table[TABLE_COUNT];
        pde_2mb_64* pd_2mb_table[TABLE_COUNT];
    };

    pte_64* pt_table[TABLE_COUNT];

    // memcpy slots
    pdpte_1gb_64* memcpy_pdpt_1gb_table;
    pde_2mb_64* memcpy_pd_2mb_table;
    pte_64* memcpy_pt_table;

    uint32_t memcpy_pml4e_idx;
    uint32_t memcpy_pdpt_idx;
    uint32_t memcpy_pdpt_large_idx;
    uint32_t memcpy_pd_idx;
    uint32_t memcpy_pd_large_idx;
    uint32_t memcpy_pt_idx;

    bool is_pdpt_table_occupied[TABLE_COUNT];
    bool is_pd_table_occupied[TABLE_COUNT];
    bool is_pt_table_occupied[TABLE_COUNT];

    remapped_entry_t remapping_list[REMAPPING_COUNT];
};
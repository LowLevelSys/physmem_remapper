#pragma once
#include "../project_includes.hpp"

constexpr uint64_t TABLE_COUNT = 50;

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
        UINT64 offset_1gb : 30;
        UINT64 pdpt_idx : 9;
        UINT64 pml4e_idx : 9;
        UINT64 reserved : 16;
    };

    struct {
        UINT64 offset_2mb : 21;
        UINT64 pd_idx : 9;
        UINT64 pdpte_idx : 9;
        UINT64 pml4e_idx : 9;
        UINT64 reserved : 16;
    };

    struct {
        UINT64 offset_4kb : 12;
        UINT64 pt_idx : 9;
        UINT64 pd_idx : 9;
        UINT64 pdpte_idx : 9;
        UINT64 pml4e_idx : 9;
        UINT64 reserved : 16;
    };

    uint64_t flags;
} va_64;

struct constructed_page_tables {
    // We copy the top layer of pml4's and insert a new entry for memory copying util
    pml4e_64* pml4_table;

    // These are here for remapping
    union {
        pdpte_64* pdpt_table[TABLE_COUNT];
        pdpte_1gb_64* pdpt_1gb_table[TABLE_COUNT];
    };
    union {
        pde_64* pde_table[TABLE_COUNT];
        pde_2mb_64* pde_2mb_table[TABLE_COUNT];
    };

    pte_64* pte_table[TABLE_COUNT];

    uint32_t used_pml4e_slot;

    bool is_pdpt_table_occupied[TABLE_COUNT];
    bool is_pd_table_occupied[TABLE_COUNT];
    bool is_pt_table_occupied[TABLE_COUNT];
};
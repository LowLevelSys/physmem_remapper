#pragma once
#include "../includes/includes.hpp"
#include "../idt/safe_crt.hpp"

#include "physmem_structs.hpp"
#include "physmem.hpp"

// Helper functions for remapping
uint32_t get_free_pdpt_table_index(page_table_t* inst);
uint32_t get_free_pde_table_index(page_table_t* inst);
uint32_t get_free_pte_table_index(page_table_t* inst);

// Debug functions for remapping
bool log_paging_hierarchy(uint64_t va, paging_structs::cr3 target_cr3);

// The main remapping function
bool remap_outside_virtual_address(uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3);
bool ensure_address_space_mapping(uint64_t base, uint64_t size, paging_structs::cr3 outside_cr3);

#define ENABLE_REMAPPING_LOGGING

#ifdef ENABLE_REMAPPING_LOGGING
#define dbg_log_remapping(fmt, ...) dbg_log("[REMAPPING] " fmt, ##__VA_ARGS__)
#else
#define dbg_log_remapping(fmt, ...) (void)0
#endif